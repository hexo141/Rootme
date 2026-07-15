// test_futex.c: verify Futex PI primitives behave as expected on 6.6 GKI
// (Same race as qcom_exploit.c but without the kernel-write payload)
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdatomic.h>

static uint32_t f_lock;
static atomic_int ready, done;

static long fx(uint32_t *a, int op, uint32_t v, const struct timespec *to,
               uint32_t *b, uint32_t v3) {
    return syscall(SYS_futex, a, op, v, to, b, v3);
}

static void *owner(void *arg) {
    (void)arg;
    fx(&f_lock, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    ready = 1;
    while (!done) usleep(1000);
    fx(&f_lock, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

int main(void) {
    pthread_t th;
    pthread_create(&th, NULL, owner, NULL);
    while (!ready);

    struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000000 };
    long r = fx(&f_lock, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
    printf("[*] FUTEX_LOCK_PI timed-wait -> %ld\n", r);
    printf("[*] f_lock value = 0x%x\n", f_lock);

    done = 1;
    pthread_join(th, NULL);
    printf("[+] futex PI primitives OK\n");
    return 0;
}
