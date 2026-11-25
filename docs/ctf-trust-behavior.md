# CTF 场景下的信任边界与行为检测设计

记录时间：2026-11-25
适用版本：karma 0.41.0
适用范围：CTF / 靶场容器，目标生命周期短，没有可信基线

## 1. 约束

- 靶机通常是全新容器，攻击者投放的文件与业务文件同一批创建，mtime 聚类和基线差分没有稳定价值。
- 攻击者会改文件名、变量名、服务名，关键字表无法穷尽。
- 时间有限，检查必须快，不能做全盘哈希或长时间基线采集。
- 容器经常没有 systemd 总线，`systemctl list-units` 不可用，但 unit 文件仍可能存在。
- karma 只读，不能在目标上安装 agent、写文件或启动进程。

## 2. 核心判据

把每个持久化/外联行为表示成一条启动边：

```text
触发点 → 机制 → 目标
```

对每条边只问四个问题：

1. 触发点是否位于管理员可写层（`/etc/profile.d`、`/etc/systemd/system`、`/etc/cron*`、`/etc/rc.local`、`/opt`、`/var/lib`、`/usr/local`）？
2. 目标是否由发行版包管理、是否位于受信根目录？
3. 目标的属主和权限是否允许非 root 修改？
4. 目标具备什么能力：执行、网络、读环境、写文件、解码？

名字只用于展示，不参与评分。

## 3. 数据模型

```go
type Trust struct {
    PackageOwned  bool // dpkg -S / rpm -qf 能查到
    InTrustedRoot bool // /usr/bin、/usr/lib、/lib/systemd/system 等
    RootOwned     bool
    Writable      bool // group/other 可写
    Executable    bool
}

type Edge struct {
    Trigger   string   // /etc/profile.d/foo.sh
    Mechanism string   // export / source / ExecStart / URL / cron
    Target    string   // 文件路径或 host:port
    Trust     Trust
    Sinks     []string // exec / socket / file_write / eval
}
```

当前案例的边：

```text
/etc/profile.d/vendor-runtime-loader.sh
  --export--> /var/lib/vendor/runtime/.attach-loader.sh
  --source--> VENDOR_RUNTIME_ATTACH_ROUTE / VENDOR_RUNTIME_TOKEN

/etc/systemd/system/attachment-previewd.service
  --ExecStart--> /usr/local/libexec/attachment-previewd

/opt/vendor/config/portal/vendor-sync.env
  --URL--> 198.51.100.25:8443
/opt/vendor/tools/vendor-sync-probe
  --socket.connect--> 上述 URL

/proc/36
  --interpreter--> /usr/local/bin/thumbcache-minerd
```

## 4. 信任判定

受信根目录：

```text
/bin /sbin /usr/bin /usr/sbin
/lib /lib64 /usr/lib /usr/lib64 /usr/libexec
/lib/systemd/system /usr/lib/systemd/system
```

管理员层：

```text
/etc/profile.d /etc/profile /etc/bash.bashrc
/etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system
/etc/cron* /var/spool/cron
/etc/rc.local /etc/init.d
/opt /srv /var/lib /usr/local
/home/*/.config/systemd /home/*/.config/autostart
```

判定顺序：

1. 目标能被 dpkg/rpm 查到 → 低风险，除非文件被修改或权限异常。
2. 目标在受信根目录、root 属主、组/其他不可写 → 低风险。
3. 目标在管理员层、无包归属 → 候选。
4. 目标有执行位或隐藏文件名 → 升级。
5. 目标被启动边引用 → 升级。

CTF 中包管理数据库通常未被污染，可以直接作为信任源；攻击者投放的脚本、unit、probe 都不在包数据库里。

## 5. 行为判定

### 5.1 启动面解析

| 触发面 | 解析内容 |
| --- | --- |
| shell 启动文件 | `export`、`source`、`.`、命令替换、`eval` |
| systemd unit | `ExecStart`、`ExecStartPre`、`EnvironmentFile`、`User`、`Restart` |
| cron | 命令字段、`@reboot` |
| udev | `RUN+=`、`PROGRAM=`、`IMPORT{program}` |
| ld.so.preload | 每个 preload 路径 |
| XDG autostart | `Exec=` |
| rc.local / init.d | 可执行脚本 |

shell 解析建议用 `mvdan.cc/sh/v3/syntax`，拿 AST 里的赋值、source、重定向和命令替换；systemd 用小型 INI 解析器。

### 5.2 能力识别

| 能力 | 识别方式 |
| --- | --- |
| exec | shell 的 `eval`/`exec`/`source`，Python 的 `os.system`/`subprocess`，ELF 的 `execve`/`system` 导入 |
| network | `socket.connect`、`requests.*`、`urllib.*`、`curl`、`wget`、`/dev/tcp`，ELF 的 `socket`/`connect` |
| env | 读取 `os.environ`、`$VAR`、`EnvironmentFile` |
| file_write | 重定向、`open(..., "w")`、`write` 导入 |
| decode | `base64 -d`、`base64_decode`、`gzinflate`、`str_rot13` |

### 5.3 评分

| 条件 | 级别 |
| --- | --- |
| 启动边指向无包归属、非受信根目录的可执行文件 | high |
| 启动边指向无包归属的隐藏文件（`.` 开头） | high |
| unit `ExecStart` 在 `/opt`、`/var`、`/usr/local`、`/srv`、`/home` | high |
| 启动文件 `export VAR=/admin/path` 或 `source /admin/path` | medium/high |
| 无包脚本同时具备 env/file 输入和 exec/network sink | high |
| 解释器进程运行无包脚本（`bash /opt/...`、`python /var/...`） | medium/high |
| 配置/脚本含公网 URL 或非常规端口，且文件无包归属 | medium |
| unit 在管理员层但未启用 | low，近 7 天创建时 medium |

组合规则优先：单看 `export` 是 medium，`export` 指向无包隐藏脚本是 high；单看 `socket` 是 low，`socket` 的目标来自无包配置是 high。

## 6. karma 落地

新增三个内部包：

```text
internal/trust     // 包归属、受信根、权限、symlink 解析
internal/startup   // 启动面解析，产出 Edge
internal/graph     // 边评分、组合规则、证据链
```

新增检查：

```text
startup-edges        // profile.d、systemd、cron、rc.local、udev、ld.so.preload
admin-artifacts      // /opt、/var/lib、/usr/local 的无包可执行/隐藏脚本
unit-files           // unit 内容
profile-loaders      // 启动文件 export/source 链
interpreter-scripts  // 解释器 + 无包脚本进程
outbound-config      // 配置到 URL/socket 的边
```

采集沿用 `model.FileList` 的 Native/Shell 双 tier：

- Native：Go 遍历、读文件、解析 AST。
- Shell：`find` 列表 + `cat`，解析在本地做；保证两个 tier 产出同一种 Edge。

规则仍用 `model.Rule` 负责行级着色和原因文本，severity 由 `internal/graph` 的评分给出。

## 7. CTF 适配

- 容器里 systemd 不是 PID 1 时，`services` 不要只依赖 `systemctl list-units`；用 `systemctl list-unit-files --all` 和文件遍历。
- 不做基线采集；用包归属和受信根作为信任源。
- 扫描深度控制在 3–4 层，文件数上限 200–500，保证 30 秒内出结果。
- 常见 CTF 持久化面优先：profile.d、systemd、cron、rc.local、ld.so.preload、authorized_keys、web 目录。
- 允许 `--ignore` 指定操作者自己的工具路径（例如 `/root/karma`），避免把 IR 工具当成恶意文件。

## 8. 测试

- 当前四个案例各一个 fixture：systemd unit、profile.d + 隐藏 loader、`/opt` 下的 probe、解释器 + 脚本进程。
- Native 和 Shell 两个 tier 的命中必须一致。
- 误报 fixture：正常 `/etc/profile.d/java17.sh`、`/usr/local/bin` 下管理员编译的程序、官方 unit。
- 容器 fixture：systemd 总线不可用，unit 文件仍可读。
- 不做基线相关测试。

## 9. 局限

- 包数据库可以被篡改；CTF 中概率低，必要时用文件哈希校验关键路径。
- shell 的 `eval`、变量拼接、编码混淆会绕过静态 AST；用运行时进程/连接补。
- 攻击者把 payload 放进包管理目录并伪造包记录时，信任模型会失效；这是低概率高成本路径。
- 该设计定位为快速 IR 辅助，目标是“把可疑启动边和危险能力摆到操作者面前”，不替代人工判断。

更细的缺口分析见：

- `docs/systemd-unit-persistence.md`
- `docs/env-injection-persistence.md`