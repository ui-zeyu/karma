# `karma local watch`：短连接监听设计

## 目标

在目标主机上没有 `ss`、`conntrack`、`tcpdump`、`tshark` 时，持续观察新发起的连接，
避免 `ss -nltp` 只看到监听端口、看不到短连接。

只在 Linux 本地运行，直接读内核 `sock_diag`，不依赖任何外部工具。

## 命令形态

```bash
karma local watch [--interval 100ms] [--duration 0] [--all]
```

`watch` 作为 `karma local` 的子命令，和现有的 `cat`、`ls` 并列。

## 原理

1. 用 `netlink.SocketDiagTCP` / `SocketDiagUDP` 分别 dump IPv4 和 IPv6 的 socket 表。
2. 第一次快照作为基线，只记录不输出。
3. 之后每个 `--interval` 取一次快照，按
   `proto + local + peer + inode` 做增量比较，新出现的 socket 才输出。
4. 对新增 socket 用 `/proc/<pid>/fd` 的 `socket:[inode]` 反查持有进程：
   root 能看到所有进程，普通用户只能看到自己的。
5. 输出后保留一段时间的 key，避免同一个 socket 因状态变化重复打印。

关键点：TCP 连接正常关闭后会在 `TIME_WAIT` 停留约 60 秒，所以即使 ESTAB 阶段只有
几十毫秒，100ms 一次的轮询也能看到它。短连接不会因为轮询间隔而完全消失。

## 输出

```text
2026-11-25 15:02:11.482  tcp  ESTAB     172.24.0.2:49812 -> 198.51.100.25:8443  pid=1234 comm=curl
2026-11-25 15:02:11.913  tcp  TIME-WAIT 172.24.0.2:49812 -> 198.51.100.25:8443  pid=- comm=-
```

字段：时间、协议、状态、本地地址、远端地址、持有进程。

默认跳过 `LISTEN` 和 UDP 的 `UNCONN`。`--all` 会连启动时已存在的 socket 和监听端口
一起输出，适合先看全量基线。

## 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--interval` | `100ms` | 轮询间隔，最小 10ms |
| `--duration` | `0` | 运行时长，0 表示直到 Ctrl-C |
| `--all` | `false` | 包含启动时已存在的 socket 和监听端口 |

## 局限

- UDP 短报文在 socket 关闭后没有 `TIME_WAIT`，可能漏掉。
- TCP 被 RST 拒绝的连接可能不进入 `TIME_WAIT`，低间隔能提高命中率，但不能保证 100%。
- 非 root 只能把 socket 归到自己的进程。
- 容器里要跑在目标网络命名空间内；从宿主机看容器需要 `nsenter -t <pid> -n`。
- 高频轮询在 socket 很多的机器上有成本，默认 100ms，按需调大。

如果要保证捕获每一条 `connect()`，下一步是 eBPF tracepoint（`sys_enter_connect`）
或 perf tracepoint；当前方案先覆盖绝大多数 TCP 短连接，保持零依赖。

## 代码落点（供后续实现）

- `internal/checks/linux/native/netlink_linux.go`
  - 把 `Ss` 的 dump 逻辑抽成结构化的 `SocketSnapshot`
  - 导出 `SocketOwners`，复用现有 `socketHolders`
- `internal/watch/watch.go`
  - 基线、增量比较、格式化、退出处理，跨平台可测
- `internal/watch/source_linux.go`
  - 把 native 的 snapshot/owners 适配成 watch 的 Source
- `internal/watch/source_other.go`
  - 非 Linux 返回 “socket watch needs Linux sock_diag”
- `internal/cli/watch.go`
  - 定义 `karma local watch` 和三个参数
- `internal/cli/commands.go`
  - 在 `newLocalCmd` 里注册 `newWatchCmd()`

测试重点：基线不输出、新 socket 输出一次、状态变化不重复、`TIME_WAIT` 能输出、
监听端口默认跳过、`--all` 包含基线、无持有进程时输出 `pid=-`。