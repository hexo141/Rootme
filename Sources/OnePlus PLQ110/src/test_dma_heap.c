// test_dma_heap.c: probe /dev/dma_heap/* availability on OnePlus PLQ110
//
// On MTK 4.19 the equivalent test was test_ashmem.c.  Android GKI 6.6
// removes ASHMEM and replaces it with dma-heap system heaps.
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

struct dma_heap_allocation_data {
    unsigned long long len;
    int fd;
    unsigned int fd_flags;
    unsigned int heap_flags;
};
#define DMA_HEAP_IOC_MAGIC 'H'
#define DMA_HEAP_IOCTL_ALLOC _IOWR(DMA_HEAP_IOC_MAGIC, 0, struct dma_heap_allocation_data)

int main(void) {
    const char *heaps[] = {
        "/dev/dma_heap/system",
        "/dev/dma_heap/system-uncached",
        "/dev/dma_heap/qcom-system",
        "/dev/dma_heap/cma",
        "/dev/dma_heap/qcom-display",
        NULL,
    };
    for (int i = 0; heaps[i]; i++) {
        int fd = open(heaps[i], O_RDONLY | O_CLOEXEC);
        printf("[*] open %s -> fd=%d\n", heaps[i], fd);
        if (fd < 0) continue;

        struct dma_heap_allocation_data data = {
            .len = 4096 * 4,
            .fd_flags  = O_RDWR | O_CLOEXEC,
            .heap_flags = 0,
        };
        int r = ioctl(fd, DMA_HEAP_IOCTL_ALLOC, &data);
        printf("    ioctl ALLOC len=%llu -> r=%d dma_buf_fd=%d\n",
               (unsigned long long)data.len, r, data.fd);
        if (data.fd >= 0) {
            void *m = mmap(NULL, 4096 * 4, PROT_READ|PROT_WRITE, MAP_SHARED, data.fd, 0);
            printf("    mmap -> %p\n", m);
            if (m && m != (void*)-1) {
                memset(m, 0xAA, 4096);
                munmap(m, 4096 * 4);
            }
            close(data.fd);
        }
        close(fd);
    }
    return 0;
}
