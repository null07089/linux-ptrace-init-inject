# linux-ptrace-init-inject

[English](README.md) | [中文](README.zh-CN.md)

A single-file Linux `ptrace` process injection tool. It attaches to a target
process (PID 1 by default), executes a command inside the target's address
space, reads back the return value, restores the original state and detaches.

The command is executed through one of two paths, chosen automatically at
runtime:

| Path | Condition | Mechanism |
|------|-----------|-----------|
| `system()` injection | the `system` symbol can be resolved in the target libc | forge a call frame and run `system(cmd)` |
| raw syscall payload | `system` cannot be resolved (e.g. stripped libc) and the architecture is x86_64 / aarch64 | generate machine code that runs `fork/clone + execve("/bin/sh", "-c", cmd) + wait4` inside the target |

> **Warning**: this program requires root (or `CAP_SYS_PTRACE`), globally
> disables SELinux, and injects code into the init process. It can make the
> system unstable or unbootable. Use it only in authorized test environments.

## Features

- One `main.cpp`, no dependencies beyond libc / libstdc++ (or `-static`).
- Two execution paths, auto-selected: target `system()`, or a generated
  raw-syscall `fork/clone + execve` payload.
- Hand-written ELF parser (no libelf/bfd) for dynamic symbol lookup; stripped
  libc gracefully falls through to the payload path.
- Register and calling-convention abstraction for x86_64, aarch64 and arm32.
- Bulk memory reads via `process_vm_readv` with a `PTRACE_PEEKDATA` fallback.
- Overwritten code and saved registers are restored before detaching.

## Repository layout

```
.
├── main.cpp          # injector source (single file)
├── Makefile          # build: make / make static / make clean
├── LICENSE           # GNU GPL v2
├── README.md         # this file (English)
└── README.zh-CN.md   # Chinese documentation
```

## Requirements

### Target system

- **Architectures**: x86_64, aarch64 (both paths); arm32 (`system()` path only,
  no payload fallback).
- **OS**: Linux (desktop, Android, container). On Android, `process_vm_readv`
  is used when available (API >= 23), otherwise reads fall back to
  `PTRACE_PEEKDATA`.
- **Privileges**:
  - root, or `CAP_SYS_PTRACE`;
  - `/proc/sys/kernel/yama/ptrace_scope` set to 0, or the target is an
    attachable child;
  - attaching to PID 1 additionally requires the relevant kernel protections
    to be disabled.

### Build host

- `g++` / `clang++` with C++17 (the code itself needs C++11 or later:
  `std::to_string`, lambdas, `auto`).
- Linux headers (`elf.h`, `sys/ptrace.h`, `sys/user.h`, ...).
- Static linking is supported for portable delivery.

## Build

```sh
make            # dynamic link -> ./inject
make static     # static link  -> ./inject (portable single binary)
make clean
```

Or manually:

```sh
g++ -O2 -std=c++17 -o inject main.cpp
g++ -O2 -std=c++17 -static -o inject main.cpp
```

## Usage

```sh
sudo ./inject
```

The following values are hard-coded in `main()` and require a rebuild to
change:

| Variable | Location | Default | Description |
|----------|----------|---------|-------------|
| target PID | `main()` | `1` | `pid_t pid = 1;` |
| command | `main()` | `touch /tmp/hello` | `const char* cmd = ...` |
| wait timeout | `main()` | 30000 ms | `wait_for_call(..., 30000)` |

### Example output

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

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | command completed (`CALL_DONE`) |
| 1 | initialization/injection error (SELinux, attach, memory, registers, ...) |
| 2 | command did not finish within the timeout, or the target died |

## How it works

```
main()
 ├─ write "0" to /sys/fs/selinux/enforce (if present)
 ├─ PTRACE_ATTACH(pid) + waitpid until the target stops
 ├─ save the original registers
 ├─ target_libc() locates the libc base
 │    └─ elf_symbol_offset() parses libc on disk to get system's offset
 ├─ branch:
 │    ├─ system found:
 │    │    ├─ find_scratch() looks for writable memory
 │    │    ├─ write the cmd string + a trap instruction (int3 / brk #0)
 │    │    └─ apply_call() forges the call frame
 │    └─ system not found (x86_64/aarch64):
 │         ├─ find_shell() picks a shell path available to the target
 │         ├─ build_exec_payload() generates fork/execve/wait4 machine code
 │         ├─ find executable memory, back up the original bytes
 │         └─ write status/argv/sh/-c/cmd/payload
 ├─ PTRACE_CONT
 ├─ wait_for_call() polls for SIGTRAP (or SIGSEGV/SIGILL at the stub PC)
 ├─ read the return register and print $1 = ...
 ├─ restore overwritten code and registers, then PTRACE_DETACH
 └─ print the SELinux reminder
```

### Memory maps

- `parse_maps(pid)`: parses `/proc/<pid>/maps` into regions with start, end,
  offset, path and r/w/x permissions.
- `target_libc(pid, &base, &path)`: finds the first mapping whose file name
  starts with `libc.so`; `base = start - offset`.

### ELF symbol resolution

- `read_file(path, out)`: loads the whole ELF into memory.
- `elf_symbol_offset(path, "system")`: a hand-written parser that does **not**
  depend on libelf/bfd:
  1. validate the ELF magic, little-endian, 32/64-bit class;
  2. walk Program Headers, take `min(p_vaddr - p_offset)` as the load bias and
     remember the `PT_DYNAMIC` location;
  3. walk Section Headers to find the `SHT_DYNSYM` size and derive the symbol
     count;
  4. read `DT_SYMTAB`, `DT_STRTAB`, `DT_STRSZ`, `DT_SYMENT` from the dynamic
     segment;
  5. iterate the dynamic symbol table matching the target name (skipping
     `st_name == 0` and `SHN_UNDEF`);
  6. return `st_value - bias` (offset relative to the load base).
- Note: if the libc section headers are stripped, `SHT_DYNSYM` is unavailable,
  the function returns 0 and the program switches to the raw payload path
  (arm32 reports an error and exits instead).

### Target memory access

- `peek_word` / `poke_word`: `PTRACE_PEEKDATA` / `PTRACE_POKEDATA`.
- `write_bytes(pid, addr, buf, len)`: handles unaligned head/tail words and
  writes whole `long`s in the middle.
- `read_bytes(pid, addr, buf, len)`: prefers `process_vm_readv` (bulk read)
  and falls back to word-by-word peeks when it fails.

### Registers and architecture abstraction

- `Regs` is architecture-dependent: `user_regs_struct` (x86_64/aarch64) or
  `user_regs` (arm32).
- `get_regs` / `set_regs`: `PTRACE_GETREGSET/SETREGSET` with `NT_PRSTATUS`,
  unified across architectures.
- `reg_pc/reg_sp/reg_ret`: PC / SP / return-value registers (x86: `rip/rsp/rax`;
  aarch64: `pc/sp/x0`; arm32: `15/13/0`).
- `apply_call(pid, regs, fn, arg, stub)`:
  - x86_64: align the stack, push `stub` as the return address, `rdi=arg`,
    `rip=fn`;
  - aarch64: `x0=arg`, `x30=stub`, `pc=fn`, move the stack down 128 bytes;
  - arm32: `r0/r14/r15`, move the stack down 128 bytes.
- `trap_bytes()`: `0xCC` (int3) on x86, `brk #0` / `bkpt` on ARM. When the
  called function returns it lands on this instruction, which delivers
  SIGTRAP and hands control back to the tracer.

### Raw syscall payload

`build_exec_payload(status_addr, sh_addr, argv_addr)` generates machine code
at runtime:

- **x86_64**:
  - `fork(57)` → parent: `wait4(61)` writes the status to `status_addr`,
    `mov rax,[status]`, `int3`;
  - child: `execve(59)`, on failure `exit(127)`;
  - failure branch: `rax = -1`, `int3`.
- **aarch64**:
  - `clone(SIGCHLD)` (220) → parent: `wait4` (260), `ldr x0,[x1]`, `b trap`;
  - child: `execve` (221), on failure `exit(93)`;
  - failure branch: `movn x0,#0`, `brk #0`.
  - 64-bit immediates are assembled with `movz/movk`, forward branches are
    patched at the end.
- Data layout (written by `main`):

```
scratch + 0            : status (8B)
scratch + 8            : argv[4] = {sh, "-c", cmd, NULL} (32B)
scratch + 40           : shell path string
...                    : "-c"
...                    : cmd
code_addr              : payload machine code
code_addr + size - N   : trap instruction (x86 N=1, ARM N=4)
```

### Scratch / executable memory selection

- `find_scratch(pid, sp, need)`:
  1. prefer a read/write region around `sp - 0x2000` that can hold `need`
     bytes;
  2. otherwise pick an anonymous, writable, non-executable region of at least
     `need + 0x1000` bytes and use `start + 0x1000`.
- The raw payload path also needs executable memory: it prefers the region
  containing the current PC (if large enough), otherwise any executable,
  non-`[vdso]` region with enough space. The original bytes are backed up in
  `saved_code` and restored afterwards.

### Waiting and cleanup

`wait_for_call(pid, stub_addr, timeout_ms)`:

- polls with `waitpid(WNOHANG)` every 10 ms;
- `SIGTRAP` → `CALL_DONE`;
- `SIGSEGV` / `SIGILL` with PC equal to the stub → `CALL_DONE`;
- `SIGSTOP` → continue running;
- more than 5 consecutive other `SIGSEGV/SIGILL` → `CALL_FAILED`;
- target exit / termination by signal → `CALL_FAILED`;
- timeout → `CALL_TIMEOUT` (sends `SIGSTOP` and blocks, the state is still
  restored afterwards).

## Known limitations and risks

- **Section-header dependency**: `elf_symbol_offset` derives the symbol count
  from `SHT_DYNSYM`; stripped section headers make parsing fail and fall back
  to the raw payload path (arm32 exits with an error instead).
- **Overwriting running code**: the raw payload path may overwrite the
  target's current instruction stream (multi-threaded races included).
  Although restored afterwards, crashes are possible.
- **Writing near the stack**: `find_scratch` prefers `sp - 0x2000`, which may
  clobber target stack frames.
- **SELinux side effect**: SELinux is globally disabled and not restored on
  exit.
- **PID 1 specifics**: a failed injection into init can hang or crash the
  system; the SIGSTOP fallback can also freeze it.
- **Little-endian only**: the ELF parser only accepts `ELFDATA2LSB`.
- **Memory write width**: `write_bytes` operates in host `long` units; no
  special handling for cross-architecture cases (e.g. an x86_64 tracer
  manipulating a 32-bit target).

## Key functions

| Function | Line | Purpose |
|----------|------|---------|
| `parse_maps` | 51 | parse `/proc/<pid>/maps` |
| `target_libc` | 80 | locate the target libc base and path |
| `read_file` | 93 | read a whole file |
| `cstr_eq` | 109 | compare a C string inside a buffer |
| `elf_symbol_offset` | 119 | hand-written ELF parser for symbol offsets |
| `find_scratch` | 239 | find writable scratch memory |
| `peek_word` / `poke_word` | 253 / 259 | single-word memory read/write |
| `write_bytes` | 263 | alignment-safe memory write |
| `get_regs` / `set_regs` | 293 / 298 | read/write target registers |
| `apply_call` | 307 / 323 / 341 | forge a call frame per architecture |
| `read_bytes` | 356 | memory read (`process_vm_readv` + fallback) |
| `find_shell` | 374 | choose a shell usable by the target |
| `build_exec_payload` | 388 / 437 | generate the x86_64 / aarch64 payload |
| `wait_for_call` | 505 | poll until the call completes |
| `main` | 537 | top-level flow |

## License

This project is licensed under the **GNU General Public License v2.0 (or
later)** — see [`LICENSE`](LICENSE). The source file carries
`SPDX-License-Identifier: GPL-2.0-or-later`.

## Credits

- Author: null07089.
- The ELF parser, architecture abstractions and generated payloads are
  hand-written and depend only on the Linux kernel UAPI headers.
