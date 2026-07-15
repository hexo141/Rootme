// test_openat.c: probe what file paths are accessible on OnePlus PLQ110
// without privilege. Useful to confirm SELinux domain restrictions before
// running the full exploit chain.
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
static const char *paths[] = {
    "/proc/version",
    "/proc/self/maps",
    "/proc/kallsyms",
    "/dev/dma_heap/system",
    "/dev/ashmem",         // should NOT exist on 6.6 GKI
    "/dev/__null__",
    "/sys/kernel/vmcoreinfo",
    "/system/bin/sh",
    NULL,
};
int main(void) {
    for (int i = 0; paths[i]; i++) {
        int fd = openat(AT_FDCWD, paths[i], O_RDONLY);
        printf("[*] openat %s -> fd=%d\n", paths[i], fd);
        if (fd >= 0) close(fd);
    }
    return 0;
}
