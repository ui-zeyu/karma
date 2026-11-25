# 环境注入型持久化检测缺口：vendor-runtime-loader 案例

记录时间：2026-11-25
适用版本：karma 0.41.0
案例：供应商工单平台容器中的任务 5 残留

## 1. 案例事实

三处残留：

```text
/opt/vendor/tools/vendor-sync-probe              root:root 755
/etc/profile.d/vendor-runtime-loader.sh          root:root 644
/var/lib/vendor/runtime/.attach-loader.sh        root:root 755
```

内容：

```bash
# /etc/profile.d/vendor-runtime-loader.sh
export VENDOR_RUNTIME_LOADER=/var/lib/vendor/runtime/.attach-loader.sh

# /var/lib/vendor/runtime/.attach-loader.sh
#!/bin/bash
export VENDOR_RUNTIME_ATTACH_ROUTE="/debug/vendor-ops"
export VENDOR_RUNTIME_TOKEN="VendorBridge-Token"
```

登录 shell 会经 `/etc/profile` → `run-parts /etc/profile.d/*.sh` 读到第一条 export，
把隐藏 loader 的路径放进环境；后续会话 source 该路径即可恢复 `/debug/vendor-ops`
的路由和请求头。

## 2. karma 当前为什么没有命中

### 2.1 `shell-rc` 读到了文件，但没有规则匹配

`internal/checks/linux/persistence.go:72` 的 `shellRcPaths` 包含 `/etc/profile.d/*`，
所以 `shell-rc` 确实读取了 `vendor-runtime-loader.sh`。它的规则只有：

```go
Rules: []model.Matcher{aliasShadowRule, historyOffRule, define.KeywordRule}
```

`define.KeywordRule` 匹配的是：

```text
\b(?:flags?|ctf|secrets?|keys?|passwords?)\b
```

`export VENDOR_RUNTIME_LOADER=/var/lib/vendor/runtime/.attach-loader.sh` 不含这些词，
所以该行只作为普通内容显示，没有 severity，也没有 reason。

实测 `karma ssh ... shell-rc` 的输出：

```text
/etc/profile.d/vendor-runtime-loader.sh
export VENDOR_RUNTIME_LOADER=/var/lib/vendor/runtime/.attach-loader.sh
```

没有 `⟨...⟩` 注释，也没有颜色级别。

### 2.2 隐藏 loader 不在任何读取面里

`/var/lib/vendor/runtime/.attach-loader.sh` 不在 `shellRcPaths` 中。

`persistence/unit-dirs` 只读 `/etc/systemd/system` 等目录；`filesystem` 的
`keyDirs` 是 `/`、`/home`、`/opt`、`/root`、`/srv`、`/usr/local`，且只做
`-maxdepth 1` 的列表，`/var/lib/vendor` 不在其中。

`package/unowned-files` 的 `unownedDirs` 是：

```text
/bin /sbin /usr/bin /usr/sbin /lib /lib64 /usr/lib /usr/lib64 /usr/libexec
```

`/opt`、`/var/lib`、`/usr/local` 都被排除。

因此 loader 文件既不会被内容规则读到，也不会作为无主文件被标记。

### 2.3 probe 被 webshell 扫描的文件名白名单跳过

`webshell-grep` 的根目录包含 `/opt`，但文件名只收：

```text
*.php  *.phtml  *.inc
```

`vendor-sync-probe` 没有扩展名，内容也是 bash + Python，不会进入 grep。
`filesystem` 对 `/opt` 的 key-dir 列表只到 `-maxdepth 1`，看到的是
`/opt/vendor` 目录，不是 `vendor/tools/vendor-sync-probe`。

### 2.4 `env` 检查看不到 login-shell 注入

`system/env` 检查运行 `env` 和 `env-sh`。SSH 通道里的 shell 不是 login shell，
不会 source `/etc/profile.d`，所以输出里没有 `VENDOR_RUNTIME_LOADER`。实测：

```text
PATH=...
SHELL=/bin/bash
```

没有 `VENDOR_*` 变量。相反，手动 `bash -lc` 能看到：

```text
VENDOR_RUNTIME_LOADER=/var/lib/vendor/runtime/.attach-loader.sh
```

即使变量出现在 env 输出里，现有规则也只覆盖：

```text
LD_LIBRARY_PATH
PATH（cwd/空项）
PYTHONPATH
KeywordRule
```

没有“变量值指向隐藏 loader/脚本”的规则。

### 2.5 token 不在 secret 关键词里

隐藏 loader 的 `VENDOR_RUNTIME_TOKEN="VendorBridge-Token"` 包含 `Token`，
`KeywordRule` 只匹配 `key`、`secret`、`password`、`flag`、`ctf`，不匹配 `token`。
即使该文件被读到，也不会命中。

### 2.6 没有数据流跟踪

karma 只读静态文件，不解析 `VENDOR_RUNTIME_LOADER` 的值，也不会沿着这个值去读
`/var/lib/vendor/runtime/.attach-loader.sh`。这类“profile.d 里只放一个路径”的
一级间接注入正好落在静态读取和关键词匹配之间。

## 3. 建议新增的检测

### 3.1 `profile-export` 规则

在 `shell-rc` 上增加针对 profile.d 的规则，而不是只靠关键词：

| 规则 id | 匹配 | 级别 | 理由 |
| --- | --- | --- | --- |
| `profile-export-loader` | `^\s*export\s+\w*(?:LOADER|RUNTIME|ATTACH|SYNC|HOOK)\w*=/` | medium | 启动文件导出运行时/加载器路径 |
| `profile-export-hidden` | 变量值指向 `/var/lib`、`/opt`、`/usr/local`、`/run` 下的隐藏文件或可执行文件 | high | 启动文件把隐藏组件注入环境 |
| `profile-export-token` | `^\s*export\s+\w*(?:TOKEN|SECRET|KEY|PASSWD)\w*=` | medium | 启动文件携带凭据/令牌（注意误报） |
| `profile-source-hidden` | `^\s*(?:\.|source)\s+.*(?:/var/lib|/opt|/usr/local|/run)/` | high | 启动文件直接 source 非标准路径脚本 |

这些规则应只在 `/etc/profile`、`/etc/profile.d/*`、`/etc/bash.bashrc`、
`/etc/environment`、用户 rc 文件上启用，避免对普通业务脚本误报。

### 3.2 跟随一级间接引用

当 `shell-rc` 读到 `export VAR=/path/to/file` 且该路径存在时，追加一次读取：

- 只跟随一层，避免递归和环路；
- 仅限 `/var/lib`、`/opt`、`/usr/local`、`/run`、`/etc` 下的普通文件；
- 单文件最多 100 行；
- 对读到的内容套用 `profile-export-token`、`profile-source-hidden` 等规则。

这样 `VENDOR_RUNTIME_LOADER` → `.attach-loader.sh` 的链条会直接出现在报告里。

### 3.3 新增 `hidden-scripts` 检查

扫描非家目录中的隐藏可执行文件：

```text
/var/lib
/var/local
/opt
/usr/local
/etc
```

条件：

- 文件名以 `.` 开头，或位于以 `.` 开头的目录；
- 有执行位；
- 不属于 dpkg/rpm 包；
- 近 N 天创建或 mtime 与所属目录明显偏离。

级别 low/medium；如果文件内容包含 `export`、`socket`、`curl`、`wget`、
`base64`、`/dev/tcp` 等，升到 high。

### 3.4 扩展 `webshell-grep` 或新增 `script-grep`

`webshell-grep` 目前只覆盖 PHP 家族。建议增加一个针对脚本的轻量检查：

```text
roots: /opt /srv /var/lib /usr/local
files: *.sh *.py *.pl *.rb 以及无扩展名但带 shebang 的可执行文件
patterns:
  socket.connect / socket.socket
  urllib.request / requests.get / requests.post
  curl / wget
  base64 -d
  /dev/tcp/
  export *_TOKEN= / export *_ROUTE=
```

只对“非包管理、非标准目录、近 N 天新增”的文件评分，控制噪声。

### 3.5 `env` 检查增加 login-shell 视角

`env` 现在跑的是通道的默认 shell。可以增加一个 probe：

```text
bash -lc 'env'
```

或直接解析 `/etc/profile`、`/etc/profile.d/*` 的 export，不依赖目标是否有 bash。
前者更真实，后者更可控；建议两者都保留，前者作为 fallback 的补充。

### 3.6 关键词规则补充

把 `token`、`loader`、`attach` 加入高置信度组合，而不是单独匹配：

```text
(?:TOKEN|SECRET|KEY)\s*=\s*["']?[A-Za-z0-9+/=_-]{8,}
```

单独匹配 `token` 会误报大量正常配置，建议只在“变量名 + 非空值 + 非标准文件”
同时成立时给 medium。

## 4. 测试用例

1. `/etc/profile.d/*.sh` 导出 `VENDOR_RUNTIME_LOADER=/var/lib/vendor/runtime/.attach-loader.sh`
   → `profile-export-loader` + `profile-export-hidden`。
2. 隐藏 loader 内容包含 `export VENDOR_RUNTIME_TOKEN=...` → 跟随读取后
   `profile-export-token`。
3. `/opt/vendor/tools/vendor-sync-probe` 无扩展名、bash + Python socket
   → `script-grep` 命中 `socket.connect`。
4. 正常 `/etc/profile.d/java17.sh` 只设置 `JAVA_HOME`/`PATH` → 不命中。
5. 正常 `/usr/local/bin` 下管理员编译的二进制无包归属 → 只在
   `hidden-scripts` 的 low 级别出现，或不出现。
6. SSH 非 login shell 的 `env` 不含注入变量，`bash -lc env` 含注入变量
   → login-shell probe 能命中。
7. `--min-severity medium` 时 low 的 `hidden-scripts` 被过滤，high 的
   `profile-export-hidden` 保留。

## 5. 快速修复优先级

1. 在 `shell-rc` 增加 `profile-export-loader` / `profile-export-hidden` 两条规则。
2. 跟随一级 `export VAR=/path`，读取 `/var/lib`、`/opt`、`/usr/local` 下的目标。
3. 新增 `hidden-scripts` 检查，覆盖 `/var/lib` 和 `/opt`。
4. 扩展脚本扫描到 `*.sh`、`*.py` 和无扩展名 shebang 文件。
5. `env` 增加 `bash -lc env` 的 login-shell 视角。

这些改动都不需要修改现有 tier 结构，主要是新增规则、一个文件列表和一个
可选的间接读取步骤。