// kprobe: minimal kernel-base / symbol probe for OnePlus PLQ110
//
// Walks /proc/self/maps, /proc/version, /proc/kallsyms (if readable), and
// attempts to discover the KASLR slide by reading any leaked kernel
// addresses.  Print results as ASCII lines for the parent shell to parse.
//
// Compile:
//   aarch64-linux-android-clang -O2 -pie -fPIE \
//       -o kprobe kprobe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static int dump_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("[-] open %s -> errno=%d\n", path, fd);
        return -1;
    }
    char buf[4096];
    ssize_t n;
    int total = 0;
    printf("[*] === %s ===\n", path);
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        // Only print up to first 2 KB so we don't spam
        if (total + n > 2048) n = 2048 - total;
        if (n <= 0) break;
        fwrite(buf, 1, n, stdout);
        total += n;
        if (total >= 2048) {
            printf("\n[... truncated ...]\n");
            break;
        }
    }
    close(fd);
    return 0;
}

int main(void) {
    printf("[*] OnePlus PLQ110 kprobe\n");
    dump_file("/proc/version");
    dump_file("/proc/self/maps");
    dump_file("/proc/cmdline");
    dump_file("/sys/kernel/vmcoreinfo");

    // /proc/kallsyms is usually symbol stub (0x0 addrs) for unprivileged
    // users, but worth trying — modern devices sometimes leak a few.
    int ks = open("/proc/kallsyms", O_RDONLY);
    if (ks >= 0) {
        char buf[2048];
        ssize_t n = read(ks, buf, sizeof(buf) - 1);
        close(ks);
        if (n > 0) {
            buf[n] = 0;
            printf("[*] === /proc/kallsyms (first %zd bytes) ===\n%s", n, buf);
        }
    }

    // Probe dma-heap availability (replaces ASHMEM probe from MTK kit)
    const char *heaps[] = {
        "/dev/dma_heap/system",
        "/dev/dma_heap/system-uncached",
        "/dev/dma_heap/qcom-system",
        "/dev/dma_heap/cma",
        NULL,
    };
    for (int i = 0; heaps[i]; i++) {
        int fd = open(heaps[i], O_RDONLY);
        printf("[*] dma-heap %s -> fd=%d\n", heaps[i], fd);
        if (fd >= 0) close(fd);
    }

    // Probe PR_SET_MM availability
    long r = syscall(38, 167 /*PR_SET_MM*/, 0 /*PR_SET_MM_START_CODE*/, 0, 0, 0);
    printf("[*] PR_SET_MM(START_CODE,0) -> %ld (errno indicates capability)\n", r);

    return 0;
}
