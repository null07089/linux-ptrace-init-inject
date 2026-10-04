# main.cpp 说明文档

## 1. 概述

本项目只有一个源文件 `main.cpp`，实现了一个基于 Linux `ptrace` 的**进程注入工具**。

核心行为：

1. 尝试关闭 SELinux；
2. `PTRACE_ATTACH` 到目标进程（默认 **PID 1**）；
3. 在目标进程地址空间中执行命令（默认 `touch /tmp/hello`）；
4. 读取并打印命令返回值，恢复现场后 `PTRACE_DETACH`。

命令执行有两条路径，运行时自动选择：

| 路径 | 条件 | 方式 |
|---|---|---|
| `system()` 注入 | 能在目标 libc 中解析出 `system` 符号 | 伪造调用帧，执行 `system(cmd)` |
| 裸 syscall payload | 无法解析 `system`（如 libc 被 strip）且架构为 x86_64 / aarch64 | 动态生成机器码，在目标进程内 `fork/clone + execve("/bin/sh","-c",cmd) + wait4` |

> **警告**：该程序需要 root 权限（或 CAP_SYS_PTRACE），会全局关闭 SELinux，并向 init 进程注入代码，可能导致系统不稳定。请仅在授权的测试环境中使用。

## 2. 支持环境

- **架构**：x86_64、aarch64（64 位 ARM）、arm32（仅 `system()` 路径；无 payload 回退）
- **系统**：Linux（桌面、Android、容器均可，Android 需要 API 支持 `process_vm_readv`；不满足时自动回退 `PTRACE_PEEKDATA`）
- **权限**：
  - root，或具备 `CAP_SYS_PTRACE`
  - `/proc/sys/kernel/yama/ptrace_scope` 为 0，或目标为可 attach 的子进程
  - attach PID 1 在多数内核上还需要关闭相关保护

## 3. 编译

```bash
# 本机架构
g++ -O2 -std=c++17 -o inject main.cpp

# 静态链接（便于投递）
g++ -O2 -std=c++17 -static -o inject main.cpp
```

C++ 标准要求：C++11 及以上（代码使用 `std::to_string`、lambda、`auto`）。

## 4. 运行

```bash
sudo ./inject
```

程序中硬编码了以下内容，修改需重新编译：

| 变量 | 位置 | 默认值 | 说明 |
|---|---|---|---|
| 目标 PID | `main()` | `1` | `pid_t pid = 1;` |
| 待执行命令 | `main()` | `touch /tmp/hello` | `const char* cmd = ...` |
| 等待超时 | `main()` | 30000 ms | `wait_for_call(..., 30000)` |

### 输出示例

```
[+] attaching to pid 1
[+] target libc: /lib/x86_64-linux-gnu/libc.so.6
[+] target libc base: 0x7f...
[+] system() at: 0x7f... (offset 0x...)
[+] scratch: 0x... (cmd) / 0x... (trap stub)
[+] calling system("touch /tmp/hello")
$1 = 0
[+] detached
this program might have turned off selinux - you'll need to turn it back on yourself
```

### 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 命令执行完成（`CALL_DONE`） |
| 1 | 初始化/注入过程出错（SELinux、attach、内存、寄存器等） |
| 2 | 命令未在超时时间内完成，或目标进程死亡 |

## 5. 工作流程

```
main()
 ├─ 写入 "0" 到 /sys/fs/selinux/enforce（若存在）
 ├─ PTRACE_ATTACH(pid) + waitpid 等待停止
 ├─ 保存原始寄存器 saved
 ├─ target_libc() 定位 libc 基址
 │    └─ elf_symbol_offset() 解析磁盘上的 libc，得到 system 的偏移
 ├─ 分支：
 │    ├─ 找到 system:
 │    │    ├─ find_scratch() 找可写内存
 │    │    ├─ 写入 cmd 字符串 + trap 指令（int3 / brk #0）
 │    │    └─ apply_call() 伪造调用帧（设置参数寄存器与返回地址）
 │    └─ 未找到 system（x86_64/aarch64）:
 │         ├─ find_shell() 选择目标内的 shell 路径
 │         ├─ build_exec_payload() 生成 fork/execve/wait4 机器码
 │         ├─ 找可执行内存，备份原字节 saved_code
 │         └─ 写入 status/argv/sh/-c/cmd/payload
 ├─ PTRACE_CONT 执行
 ├─ wait_for_call() 轮询等待 SIGTRAP（或 PC 落在 stub 的 SIGSEGV/SIGILL）
 ├─ 读取返回值寄存器并打印 $1 = ...
 ├─ 还原被覆盖的代码、还原寄存器、PTRACE_DETACH
 └─ 打印 SELinux 提醒
```

## 6. 模块说明

### 6.1 内存映射

- `parse_maps(pid)`：解析 `/proc/<pid>/maps`，得到每段的起止、offset、路径、r/w/x 权限。
- `target_libc(pid, &base, &path)`：找第一个文件名以 `libc.so` 开头的映射段，`base = start - offset`。

### 6.2 ELF 符号解析

- `read_file(path, out)`：把整个 ELF 读入内存。
- `elf_symbol_offset(path, "system")`：**不依赖 libelf/bfd 的手写解析器**：
  1. 校验 ELF 魔数、小端、32/64 位；
  2. 遍历 Program Header，取 `min(p_vaddr - p_offset)` 作为加载 bias，记录 `PT_DYNAMIC` 位置；
  3. 遍历 Section Header 找到 `SHT_DYNSYM` 的大小，推算符号数量；
  4. 从 Dynamic 段读取 `DT_SYMTAB`、`DT_STRTAB`、`DT_STRSZ`、`DT_SYMENT`；
  5. 遍历动态符号表，匹配目标名字（跳过 `st_name == 0` 与 `SHN_UNDEF`）；
  6. 返回 `st_value - bias`（相对加载基址的偏移）。
- 注意：若 libc 节头被 strip，`SHT_DYNSYM` 不可得，函数返回 0，程序转入裸 payload 路径。

### 6.3 目标内存读写

- `peek_word` / `poke_word`：`PTRACE_PEEKDATA` / `PTRACE_POKEDATA`。
- `write_bytes(pid, addr, buf, len)`：处理首尾非对齐字，中间按 `long` 写入。
- `read_bytes(pid, addr, buf, len)`：优先 `process_vm_readv`（一次读多字节），失败回退逐字 peek。

### 6.4 寄存器与架构抽象

- `Regs` 由架构决定：`user_regs_struct`（x86_64/aarch64）或 `user_regs`（arm32）。
- `get_regs` / `set_regs`：`PTRACE_GETREGSET/SETREGSET` + `NT_PRSTATUS`，跨架构统一。
- `reg_pc/reg_sp/reg_ret`：取 PC / SP / 返回值寄存器（x86: `rip/rsp/rax`；aarch64: `pc/sp/x0`；arm32: `15/13/0`）。
- `apply_call(pid, regs, fn, arg, stub)`：
  - x86_64：栈对齐后压入 `stub` 作为返回地址，`rdi=arg`，`rip=fn`；
  - aarch64：`x0=arg`，`x30=stub`，`pc=fn`，栈下探 128 字节；
  - arm32：`r0/r14/r15`，栈下探 128。
- `trap_bytes()`：x86 为 `0xCC`（int3），ARM 为 `brk #0` / `bkpt`。函数返回后落到该指令，通过 SIGTRAP 把控制权交还 tracer。

### 6.5 裸 syscall payload

`build_exec_payload(status_addr, sh_addr, argv_addr)` 动态生成机器码：

- **x86_64**：
  - `fork(57)` → 父：`wait4(61)` 把状态写入 `status_addr`，`mov rax,[status]`，`int3`；
  - 子：`execve(59)`，失败 `exit(127)`；
  - 失败分支：`rax = -1`，`int3`。
- **aarch64**：
  - `clone(SIGCHLD)`(220) → 父：`wait4`(260)，`ldr x0,[x1]`，`b trap`；
  - 子：`execve`(221)，失败 `exit(93)`；
  - 失败分支：`movn x0,#0`，`brk #0`。
  - 64 位立即数由 `movz/movk` 拼装，前向跳转在末尾回填。
- 数据布局（由 `main` 写入，见下）：

```
scratch + 0            : status (8B)
scratch + 8            : argv[4] = {sh, "-c", cmd, NULL} (32B)
scratch + 40           : shell 路径字符串
...                    : "-c"
...                    : cmd
code_addr              : payload 机器码
code_addr + size - N   : trap 指令（x86 N=1，ARM N=4）
```

### 6.6 scratch / 可执行内存选择

- `find_scratch(pid, sp, need)`：
  1. 优先使用 `sp - 0x2000` 附近、可读写且能容纳 `need` 的段；
  2. 否则找一个匿名、可读写不可执行、且至少 `need + 0x1000` 的段，取 `start + 0x1000`。
- 裸 payload 路径还会寻找目标的可执行段：优先当前 PC 所在段（若有空间），否则任意够大的可执行、非 `[vdso]` 段。覆盖前会用 `saved_code` 备份，结束后还原。

### 6.7 等待与收尾

`wait_for_call(pid, stub_addr, timeout_ms)`：

- 每 10 ms 用 `waitpid(WNOHANG)` 轮询；
- `SIGTRAP` → `CALL_DONE`；
- `SIGSEGV` / `SIGILL` 且 PC 等于 stub → `CALL_DONE`；
- `SIGSTOP` → 继续运行；
- 其它 `SIGSEGV/SIGILL` 连续超过 5 次 → `CALL_FAILED`；
- 进程退出/被信号终止 → `CALL_FAILED`；
- 超时 → `CALL_TIMEOUT`（发送 `SIGSTOP` 并阻塞等待，随后仍还原现场）。

## 7. 已知限制与风险

- **节头依赖**：`elf_symbol_offset` 用 `SHT_DYNSYM` 推算符号数量；libc 节头被剥离时解析失败，转裸 payload 路径（arm32 则直接报错退出）。
- **覆盖执行中代码**：裸 payload 路径可能覆盖目标当前的指令流（含多线程竞态），虽会还原，但仍有崩溃风险。
- **栈附近写数据**：`find_scratch` 首选 `sp - 0x2000`，存在踩目标栈帧的可能。
- **SELinux 副作用**：程序会全局关闭 SELinux，退出时不会自动恢复。
- **PID 1 特殊性**：注入 init 一旦出错可能使系统挂起或崩溃；SIGSTOP 兜底也可能冻结系统。
- **小端限定**：ELF 解析仅支持 `ELFDATA2LSB`。
- **写内存限制**：`write_bytes` 按本机 `long` 宽度操作，跨架构（如 x86_64 tracer 操作 32 位目标）时未做特殊处理。

## 8. 关键函数索引

| 函数 | 行号 | 作用 |
|---|---|---|
| `parse_maps` | 45 | 解析 `/proc/<pid>/maps` |
| `target_libc` | 74 | 定位目标 libc 基址与路径 |
| `read_file` | 87 | 读取整个文件 |
| `cstr_eq` | 103 | 缓冲区内的 C 字符串比较 |
| `elf_symbol_offset` | 113 | 手写 ELF 解析，查符号偏移 |
| `find_scratch` | 233 | 查找可写 scratch 内存 |
| `peek_word` / `poke_word` | 247 / 253 | 单字内存读写 |
| `write_bytes` | 257 | 对齐安全的内存写入 |
| `get_regs` / `set_regs` | 287 / 292 | 读写目标寄存器 |
| `apply_call` | 301 / 317 / 335 | 按架构伪造函数调用帧 |
| `read_bytes` | 350 | 内存读取（readv + 回退） |
| `find_shell` | 368 | 选择目标可用的 shell |
| `build_exec_payload` | 382 / 431 | 生成 x86_64 / aarch64 payload |
| `wait_for_call` | 499 | 轮询等待调用完成 |
| `main` | 531 | 总控流程 |
