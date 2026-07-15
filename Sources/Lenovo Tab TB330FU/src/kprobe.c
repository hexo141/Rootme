// Fixed probe v4 - correct asm constraints
// clang --target=aarch64-linux-android33 -nostdlib -static -Os -fno-builtin -o kprobe kprobe.c
static long open_file(const char *path) {
    register long x8 asm("x8") = 57;
    register long x0 asm("x0") = -100;
    register long x1 asm("x1") = (long)path;
    register long x2 asm("x2") = 0;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}
static long read_fd(long fd, char *buf, long max) {
    register long x8 asm("x8") = 63;
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = max;
    asm volatile("svc #0" : "+r"(x0), "+r"(x1) : "r"(x2), "r"(x8) : "memory");
    return x0;
}
static void close_fd(long fd) {
    register long x8 asm("x8") = 57;
    register long x0 asm("x0") = fd;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
}
static void write_str(const char *s, long len) {
    register long x8 asm("x8") = 64;
    register long x0 asm("x0") = 1;
    register long x1 asm("x1") = (long)s;
    register long x2 asm("x2") = len;
    asm volatile("svc #0" : "+r"(x0), "+r"(x1) : "r"(x2), "r"(x8) : "memory");
}
static void exit_app(long code) {
    register long x8 asm("x8") = 94;
    register long x0 asm("x0") = code;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
}

static int my_len(const char *s) {
    int n = 0;
    while (*s++) n++;
    return n;
}
static void out(const char *s) { write_str(s, my_len(s)); }

void _start() {
    char buf[8192];
    long n;
    
    out("=== PROBE v4 ===\n");
    
    // /proc/version
    long fd = open_file("/proc/version");
    char tmp[16]; int p = 0;
    long val = fd;
    if (val < 0) { tmp[p++] = '-'; val = -val; }
    if (val == 0) tmp[p++] = '0';
    else { char rev[16]; int rp = 0; while (val) { rev[rp++] = '0' + (val % 10); val /= 10; } while (rp) tmp[p++] = rev[--rp]; }
    tmp[p] = 0;
    out("version_fd="); out(tmp); out("\n");
    
    if (fd >= 0) {
        n = read_fd(fd, buf, 511);
        if (n > 0) { buf[n] = 0; out("version="); out(buf); out("\n"); }
        close_fd(fd);
    }
    
    // boot_id
    fd = open_file("/proc/sys/kernel/random/boot_id");
    if (fd >= 0) {
        n = read_fd(fd, buf, 255);
        if (n > 0) { buf[n] = 0; out("boot_id="); out(buf); }
        close_fd(fd);
    } else out("boot_id=FAIL\n");
    
    // kptr_restrict
    fd = open_file("/proc/sys/kernel/kptr_restrict");
    if (fd >= 0) {
        n = read_fd(fd, buf, 15);
        if (n > 0) { buf[n] = 0; out("kptr="); out(buf); }
        close_fd(fd);
    } else out("kptr=FAIL\n");
    
    // kallsyms
    fd = open_file("/proc/kallsyms");
    if (fd >= 0) {
        n = read_fd(fd, buf, 4095);
        close_fd(fd);
        if (n > 0) {
            buf[n] = 0;
            int lines = 0;
            for (int i = 0; i < n; i++) if (buf[i] == '\n') lines++;
            char ln[16]; int lp = 0; int lv = lines;
            if (lv == 0) ln[lp++] = '0';
            else { char rev[16]; int rp = 0; while (lv) { rev[rp++] = '0' + (lv % 10); lv /= 10; } while (rp) ln[lp++] = rev[--rp]; }
            ln[lp] = 0;
            out("kallsyms_lines="); out(ln); out("\n");
            int i = 0, pr = 0;
            while (pr < 3 && i < n) {
                int s = i;
                while (i < n && buf[i] != '\n') i++;
                if (i > s) { char c = buf[i]; buf[i] = 0; out("  "); out(buf + s); out("\n"); buf[i] = c; }
                if (buf[i] == '\n') i++;
                pr++;
            }
        }
    } else out("kallsyms=EACCES\n");
    
    // maps
    fd = open_file("/proc/self/maps");
    if (fd >= 0) {
        n = read_fd(fd, buf, 4095);
        close_fd(fd);
        if (n > 0) {
            buf[n] = 0;
            out("---MAPS---\n");
            write_str(buf, n);
            out("---END---\n");
        }
    }
    
    // /dev/ashmem
    fd = open_file("/dev/ashmem");
    out("ashmem="); out(fd >= 0 ? "yes\n" : "no\n");
    if (fd >= 0) close_fd(fd);
    
    // selinux
    fd = open_file("/sys/fs/selinux/enforce");
    if (fd >= 0) {
        n = read_fd(fd, buf, 15);
        if (n > 0) { buf[n] = 0; out("selinux="); out(buf); }
        close_fd(fd);
    }
    
    // cmdline
    fd = open_file("/proc/cmdline");
    if (fd >= 0) {
        n = read_fd(fd, buf, 1023);
        if (n > 0) { buf[n] = 0; out("cmdline="); out(buf); out("\n"); }
        close_fd(fd);
    }
    
    out("=== DONE ===\n");
    exit_app(0);
    for(;;);
}
