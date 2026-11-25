# systemd unit 持久化检测缺口与改进建议

记录时间：2026-11-25
适用版本：karma 0.41.0
案例：供应商工单平台容器中的 `attachment-previewd` 后门

## 1. 案例事实

靶机为 Docker 容器，PID 1 是 supervisord，systemd 未运行。后门由三部分组成：

```text
/etc/systemd/system/attachment-previewd.service   root:root 644
/etc/systemd/system/attachment-previewd.env       root:root 644
/usr/local/libexec/attachment-previewd            root:root 755
```

unit 以 `User=root`、`Restart=always` 运行，`ExecStart` 指向 `/usr/local/libexec/attachment-previewd`，
`EnvironmentFile` 指向同目录下的 `.env`。unit 没有 `multi-user.target.wants` 软链接，
`systemctl is-enabled` 返回 `disabled`。

karma 当前没有把它标成命中，原因分布在四个检查的边界上。

## 2. 现有检查的覆盖边界

| 检查 | 数据源 | 覆盖范围 | 本例缺口 |
| --- | --- | --- | --- |
| `service/services` | `systemctl list-units --type=service --all`，失败后回退 `service --status-all` | 正在运行的服务 | systemd 未运行，命令失败；回退只看到 SysV 服务 |
| `persistence/enabled-units` | `systemctl list-unit-files --state=enabled` | 已启用的 unit | unit 未启用，被状态过滤掉 |
| `persistence/unit-dirs` | `find /etc/systemd/system -maxdepth 1` 的 mtime 列表 | 管理员层 unit 目录的文件名和 mtime | 没有 unit 内容规则；只会以 Low 的 mtime 离群点出现 |
| `package/unowned-files` | dpkg/rpm 包归属，扫描 `/bin`、`/sbin`、`/usr/bin`、`/usr/libexec` 等 | 系统目录中的无主文件 | `/usr/local` 被有意排除，payload 不在扫描范围 |

### 2.1 `service` 方面只回答运行时状态

`internal/checks/linux/service.go` 的 `services` 检查先运行：

```text
systemctl list-units --type=service --all
```

该命令需要 systemd 总线。容器里 systemd 不是 PID 1，命令直接失败，随后回退到：

```text
service --status-all
```

结果是 `procps`、`ssh`、`supervisor` 三条 SysV 记录。`attachment-previewd` 本身没有运行，
即使运行，systemd unit 也不在 SysV 的扫描面里。

### 2.2 `enabled-units` 只列已启用 unit

`internal/checks/linux/persistence.go` 中：

```go
Inv: model.NewCommand("systemctl", "list-unit-files", "--state=enabled")
```

`systemctl list-unit-files` 只读文件，不需要总线，所以它能正常工作；但 `--state=enabled`
把“存在但未启用”的 unit 排除了。后门 unit 有 `[Install] WantedBy=multi-user.target`，
但没有建立 `.wants` 软链接，因此不在结果里。

### 2.3 `unit-dirs` 有 mtime 信号，但没有 unit 语义

`unit-dirs` 调用：

```go
listingCheck("unit-dirs", "systemd unit directories (by mtime)",
    model.AspectPersistence, unitDirs, 100, nil)
```

最后一个参数是 `nil`，即没有任何 `model.Matcher`。`cluster.ListingNormalize` 会把
mtime 明显偏离主簇的文件标成 `mtime-outlier`，但级别只是 Low，原因是通用的
“mtime isolated from the main cluster (outlier)”，不会说明这是 systemd unit、也不会
提升级别。

本例的时间分布：

```text
/etc/systemd/system/attachment-previewd.service   2026-11-25 06:33
/etc/systemd/system/attachment-previewd.env       2026-11-25 06:33
其余 10 个目录                                      2026-06-15 10:47
```

用同样的 12 个条目做聚类复现，两个 unit 文件都会得到：

```text
sev=low id=mtime-outlier msg=mtime isolated from the main cluster (outlier)
```

所以 mtime 信号存在，但只有同时满足下面三个条件才可见：

1. 选中了 `persistence` 方面（`service` 方面不包含 `unit-dirs`）；
2. `--min-severity` 没有把 Low 过滤掉；
3. 操作者注意到两条普通 Low 行。

### 2.4 没有 unit 内容检查

全仓库搜索 `ExecStart` 没有结果。当前没有任何检查读取 unit 的：

- `ExecStart` / `ExecStartPre` / `ExecStop` 的路径
- `EnvironmentFile`
- `User`、`Restart`、`RuntimeMaxSec`
- `[Install]` 与实际 `.wants` 软链接的对应关系
- drop-in `*.d/*.conf`

因此“unit 文件指向 `/usr/local/libexec` 下由 root 常驻重启的脚本”这一组特征没有规则可命中。

### 2.5 `/usr/local` 不在无主文件扫描范围

`internal/checks/linux/package.go` 的注释写明 `/usr/local` 被有意排除，因为它用于管理员
自行编译安装的软件。`unownedDirs` 包含 `/usr/libexec`，不包含 `/usr/local/libexec`。
payload 因此不会被 `unowned-files` 标记。

## 3. 改进目标

1. 在 systemd 未运行、unit 未启用、unit 未加载的情况下，仍能发现管理员层的 unit 文件。
2. 读取 unit 内容并按行为分级，而不是只凭文件名和 mtime。
3. 把 unit、`ExecStart` 落点、文件归属、进程状态关联成一条证据链。
4. 控制误报：官方 `/usr/lib/systemd/system` 和 `/lib/systemd/system` 的存量 unit 不进入逐条规则。

## 4. 建议一：新增 `unit-files` 检查（优先级最高）

### 4.1 目录范围

只读管理员可写层，避免扫描发行版自带的数百个 unit：

```text
/etc/systemd/system
/etc/systemd/system/*.d
/run/systemd/system
/run/systemd/system/*.d
/usr/local/lib/systemd/system
/etc/systemd/user
/etc/systemd/user/*.d
/root/.config/systemd/user
/root/.config/systemd/user/*.d
/home/*/.config/systemd/user
/home/*/.config/systemd/user/*.d
```

`/usr/lib/systemd/system` 与 `/lib/systemd/system` 只作为基线来源：当管理员层出现同名
unit 或 drop-in 覆盖时，读取覆盖内容并提示“覆盖官方 unit”，不对存量 unit 逐条评分。

### 4.2 文件类型

```text
*.service  *.timer  *.socket  *.path  *.mount  *.target
```

优先实现 `service`、`timer`、`socket`、`path`；`mount` 和 `target` 可以后补。

### 4.3 读取方式

沿用 `model.FileList`：

- Native：新增 `native.UnitFiles(dirs)`，在进程内遍历并返回文件路径；
  `Read` 使用 `localfs.ReadBody`。
- Shell：`find <dirs> -type f \( -name '*.service' -o ... \) -print | sort | head -n N`；
  `Read` 使用 `script.ReadFile(path, "cat")`。

每个文件最多读 300 行，整次检查最多 120 个文件；超过时标记 truncated。
每个文件一个 section，标题为路径，避免文件内容伪造 section 边界。

### 4.4 unit 解析

写一个小的 INI 解析器即可，不需要引入依赖：

```go
type UnitFile struct {
    Path     string
    Sections map[string]map[string][]string // [Service] -> ExecStart -> values
}
```

保留重复键（`ExecStart` 可以出现多次），忽略注释和空行，记录 `[Install]` 的
`WantedBy` / `RequiredBy` / `Alias`。

## 5. 建议二：unit 规则与级别

| 规则 id | 匹配 | 级别 | 理由 |
| --- | --- | --- | --- |
| `unit-exec-volatile` | `ExecStart*` 指向 `/tmp`、`/var/tmp`、`/dev/shm`、`/run`、`/home`、`/opt`、`/usr/local` | high | 非常规可执行目录，常是投放落点 |
| `unit-exec-shell` | `ExecStart=/bin/(ba)?sh -c`、`python -c`、`perl -e`、`base64 -d`、`curl`/`wget` 管道 | high | unit 直接承载脚本或下载执行 |
| `unit-env-admin` | `EnvironmentFile` 位于 `/etc/systemd/system`、`/run/systemd/system`、`/usr/local/lib/systemd/system` | medium | 凭据或参数与 unit 一起投放 |
| `unit-root-restart` | `User=root` 或未设置，且 `Restart=always`，且 `ExecStart` 非常规路径 | high | root 常驻重启，符合后门形态 |
| `unit-not-enabled` | unit 存在但无 `.wants` / `.requires` 软链接，`systemctl is-enabled` 为 disabled | low（近 7 天创建时 medium） | 丢弃后未启用，靠其他机制拉起 |
| `unit-world-writable` | unit 或 drop-in 的 mode 对 group/other 可写 | high | 任意用户可改 unit |
| `unit-unowned-exec` | `ExecStart` 的二进制/脚本不属于任何 dpkg/rpm 包 | high | 与包管理器的信任链断开 |
| `unit-missing-exec` | `ExecStart` 路径不存在 | medium | 可能是分阶段投放的残留 |
| `unit-hidden` | unit 文件名以 `.` 开头 | high | 隐藏 unit 没有正常运维用途 |
| `unit-dropin-override` | 管理员层 drop-in 覆盖 `/usr/lib/systemd/system` 中的官方 unit | medium | 常见的隐蔽持久化方式 |
| `unit-recent-admin` | 管理员层 unit 的 mtime 在 7 天内，且文件无包归属 | low | 新投放的候选，交给人工复核 |

`unit-not-enabled` 单独看很弱，适合与 `unit-exec-volatile`、`unit-root-restart`、
`unit-unowned-exec` 组合；组合命中时取最高级别。

## 6. 建议三：关联分析

unit 内容只是第一层，真正有价值的是把以下事实串起来：

1. 对每个 `ExecStart` 路径做 `lstat`：是否存在、属主、mode、mtime、是否 world-writable。
2. 查询包归属：Debian 系 `dpkg -S <path>`，RedHat 系 `rpm -qf <path>`；
   查不到即为无主文件。
3. 比较 unit 与 payload 的 mtime/ctime：同一批创建时间是强关联信号。
4. 如果 `ExecStart` 是脚本，读 shebang 和文件头 20 行，识别 `bash`、`python`、
   `base64`、`dd`、`curl`、`wget` 等行为词。
5. 如果 unit 配置了 `PIDFile`，检查文件是否存在、PID 是否存活、`/proc/<pid>/cmdline`
   是否与 `ExecStart` 一致。
6. 把 `ExecStart` 路径与 `unowned-files` 的结果做交集，避免重复报告但又保留上下文。

输出上可以一个 unit 一个 section：

```text
/etc/systemd/system/attachment-previewd.service
  [Service] ExecStart=/usr/local/libexec/attachment-previewd --mode sync
  [Install] WantedBy=multi-user.target (not enabled)
  payload: exists, root:root 755, unowned, mtime 2026-11-25 06:33
  verdict: unit-exec-volatile + unit-root-restart + unit-unowned-exec (high)
```

## 7. 建议四：低改动快速修复

如果暂时不新增完整检查，可以先做这四件事：

1. **`enabled-units` 改成 `--all`**：`systemctl list-unit-files --all` 在无 systemd 总线的
   容器里也能工作（已实测），至少能把 disabled 的管理员 unit 列出来。再加一条规则：
   管理员层 unit 处于 disabled 且 mtime 较新时给 medium。
2. **给 `unit-dirs` 加一条 unit 文件规则**：匹配 `\.(service|timer|socket|path)$` 的
   mtime 离群点，把级别从 Low 提到 medium/high，理由写明“管理员层 unit 文件的 mtime
   偏离主簇”。这条改动只涉及 `persistence.go` 的 rules 参数。
3. **单独加 `local-executables` 检查**：扫描 `/usr/local/bin`、`/usr/local/sbin`、
   `/usr/local/libexec`，对无包归属、近 7 天新增、带执行位的文件给 low/medium；
   `/usr/local` 整体仍不并入 `unowned-files`，避免改变原有语义。
4. **`services` 增加 unit-file 回退**：当 `systemctl list-units` 因无 systemd 失败时，
   回退到 `systemctl list-unit-files --all`，而不是只回退到 `service --status-all`。
   这样容器场景至少能看到 unit 名称和状态。

## 8. 建议五：测试用例

新增 `internal/checks/linux/unitfiles_test.go`，至少覆盖：

1. 管理员层 unit，`ExecStart=/usr/local/libexec/foo --mode sync`，`User=root`，
   `Restart=always`，无 `.wants` 软链接 → high。
2. 官方 `/usr/lib/systemd/system` 的存量 unit → 不产生逐条命中。
3. 管理员层 drop-in 覆盖官方 unit → `unit-dropin-override`。
4. `EnvironmentFile=/etc/systemd/system/foo.env` → `unit-env-admin`。
5. unit 文件对 group/other 可写 → `unit-world-writable`。
6. `ExecStart=/bin/bash -c '...'` → `unit-exec-shell`。
7. 无 systemd 总线（容器）时，Native 和 Shell 两个 tier 仍能返回 unit 文件。
8. `--min-severity medium` 时，`unit-exec-volatile` 等 medium/high 规则仍可见；
   Low 的 `unit-not-enabled` 被过滤，但组合规则的高级别保留。
9. 同名 unit 在 `/etc/systemd/system` 与 `/usr/lib/systemd/system` 同时存在时，
   只读管理员层并提示覆盖关系。

测试数据建议放在 `testdata/unitfiles/` 下，按目录层级复刻真实路径，避免依赖宿主机的
`/etc/systemd/system`。

## 9. 建议六：实现草图

新增 `internal/checks/linux/unitfiles.go`：

```go
var unitFileDirs = []string{
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/etc/systemd/user",
    "/root/.config/systemd/user",
    "/home/*/.config/systemd/user",
}

func unitFilesTier() []model.Step {
    return []model.Step{
        {{Label: "unit-files", Inv: model.FileList{
            List: model.Native{Body: native.UnitFiles(unitFileDirs)},
            Read: func(path string) model.Invocation {
                return model.Native{Body: readFile(path, nil)}
            },
        }}},
        {{Label: "unit-files-sh", Inv: model.FileList{
            List: model.Sh(script.UnitFiles(unitFileDirs)),
            Read: func(path string) model.Invocation {
                return model.Sh(script.ReadFile(path, `cat "$f"`))
            },
        }}},
    }
}

var UnitFileChecks = []*model.Check{
    define.LinuxCheck("unit-files", "systemd unit files (admin layers)",
        model.AspectPersistence, unitFilesTier(),
        model.Options{
            Syntax: model.SyntaxBash,
            Rules: []model.Matcher{
                // unit-exec-volatile, unit-exec-shell, unit-env-admin,
                // unit-root-restart, unit-not-enabled, unit-unowned-exec ...
            },
        }),
}
```

规则匹配建议先按 section 解析，再对 `ExecStart`、`EnvironmentFile` 等键做正则，
不要对整份文件做无锚点关键词匹配，否则注释和 `Description=` 会制造误报。

## 10. 附：任务 3 的进程伪装问题

同一台靶机上的资源劫持进程：

```text
PID 36, PPID 1, root
comm:    thumbcache-mine        # 内核 15 字符截断
cmdline: /bin/bash /usr/local/bin/thumbcache-minerd
payload: /usr/local/bin/thumbcache-minerd
脚本:    while true; do dd if=/dev/zero of=/dev/null bs=1M count=8; sleep 2; done
pidfile: /run/thumbcache-minerd.pid (内容 36)
日志:    /opt/vendor/data/logs/thumbcache-minerd.log
```

这是“解释器 + 脚本”的伪装形态：`/proc/<pid>/exe` 指向 `/bin/bash`，进程名会被截断成
`thumbcache-mine`，按进程名或可执行文件路径查杀容易漏。建议后续增加一条进程规则：

- `exe` 是 `bash`/`dash`/`sh`，但 `cmdline[1]` 是 `/usr/local`、`/opt`、`/var`、`/srv`
  下的绝对路径脚本；
- 进程运行时间较长，且有规律性的 CPU 峰值或 `dd` 子进程；
- `/run`、`/var/run` 下存在同名 pidfile，且 pid 与进程匹配；
- 脚本文件无包归属，mtime 与容器创建时间一致。

这条规则与 `unit-files` 的 `ExecStart` 分析可以共用“脚本头 + 包归属 + mtime”三组事实。