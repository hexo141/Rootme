#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <time.h>

static unsigned int futex_val;

int main() {
    printf("[*] Testing futex operations...\n");
    
    // Test basic FUTEX_WAKE
    long ret = syscall(SYS_futex, &futex_val, FUTEX_WAKE, 1, NULL, NULL, 0);
    printf("[*] FUTEX_WAKE: ret=%ld\n", ret);
    
    // Test FUTEX_LOCK_PI
    ret = syscall(SYS_futex, &futex_val, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[*] FUTEX_LOCK_PI: ret=%ld\n", ret);
    
    // Test FUTEX_UNLOCK_PI
    ret = syscall(SYS_futex, &futex_val, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[*] FUTEX_UNLOCK_PI: ret=%ld\n", ret);
    
    printf("[*] All futex operations available!\n");
    
    // Test memfd
    int fd = syscall(SYS_memfd_create, "test", 0);
    printf("[*] memfd_create: fd=%d\n", fd);
    if (fd >= 0) close(fd);
    
    // Test pipe
    int p[2];
    if (pipe(p) == 0) {
        printf("[*] pipe: ok (%d, %d)\n", p[0], p[1]);
        close(p[0]); close(p[1]);
    }
    
    return 0;
}
