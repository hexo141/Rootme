#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define __ASHMEMIOC 0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[256])
#define ASHMEM_SET_SIZE _IOW(__ASHMEMIOC, 3, unsigned long)

int main() {
    printf("[*] Opening /dev/ashmem...\n");
    int fd = open("/dev/ashmem", O_RDWR);
    if (fd < 0) { perror("ashmem open failed"); return 1; }
    printf("[+] ashmem fd = %d\n", fd);
    
    // Set name
    if (ioctl(fd, ASHMEM_SET_NAME, "test") < 0)
        perror("set name failed");
    else
        printf("[+] ashmem name set\n");
    
    // Set size
    unsigned long size = 0x100000;
    if (ioctl(fd, ASHMEM_SET_SIZE, size) < 0)
        perror("set size failed");
    else
        printf("[+] ashmem size set to 0x%lx\n", size);
    
    // mmap
    void *map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED)
        perror("mmap failed");
    else {
        printf("[+] ashmem mmap at %p\n", map);
        memset(map, 0x41, 4096);
        printf("[+] ashmem write OK\n");
        munmap(map, size);
    }
    
    close(fd);
    printf("[*] ashmem test complete\n");
    return 0;
}
