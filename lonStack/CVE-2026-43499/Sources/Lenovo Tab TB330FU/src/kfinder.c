// Minimal kernel base finder using futex hash collision technique
// Compile: clang --target=aarch64-linux-android33 -nostdlib -static -Os -fno-builtin -o kf inder kfinder.c

static long sc3(long n, long a1, long a2, long a3) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a1;
    register long x1 asm("x1") = a2;
    register long x2 asm("x2") = a3;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}
static long sc2(long n, long a1, long a2) { return sc3(n, a1, a2, 0); }
static long sc1(long n, long a1) { return sc3(n, a1, 0, 0); }
static int my_len(const char *s) { int n=0; while(*s++) n++; return n; }
static void outs(const char *s) { sc3(64, 1, (long)s, my_len(s)); }

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

void _start() {
    unsigned int futex_val = 0;
    char buf[128];
    
    outs("=== KERNEL FINDER ===\n");
    
    // Test 1: basic futex operations
    long ret = sc3(94, (long)&futex_val, FUTEX_WAKE, 1, 0, 0, 0);
    
    // Write result as hex
    // Simple hex converter
    outs("futex_wake=");
    int i;
    for (i = 7; i >= 0; i--) {
        int nib = (ret >> (i*4)) & 0xf;
        buf[7-i] = nib < 10 ? '0' + nib : 'a' + nib - 10;
    }
    buf[8] = '\n';
    sc3(64, 1, (long)buf, 9);
    
    // Test 2: memory probe via /proc/self/maps (try direct open)
    outs("maps_test=");
    long fd = sc3(56, (long)"/proc/self/maps", 0, 0);
    if (fd >= 0) {
        outs("ok\n");
        long n = sc3(63, fd, (long)buf, 127);
        sc1(57, fd);
        if (n > 0) {
            buf[n] = 0;
            outs(buf);
        }
    } else {
        outs("err:");
        // Convert negative value
        long val = fd;
        char tmp[16]; int p = 0;
        if (val < 0) { tmp[p++] = '-'; val = -val; }
        if (val == 0) tmp[p++] = '0';
        else { char rev[16]; int rp = 0; while(val) { rev[rp++]='0'+(val%10); val/=10; } while(rp) tmp[p++]=rev[--rp]; }
        tmp[p]=0;
        outs(tmp);
        outs("\n");
    }
    
    // Test 3: /proc/version
    fd = sc3(56, (long)"/proc/version", 0, 0);
    if (fd >= 0) {
        long n = sc3(63, fd, (long)buf, 127);
        sc1(57, fd);
        if (n > 0) { buf[n] = 0; outs("ver="); outs(buf); }
    }
    
    // Test 4: Using openat (AT_FDCWD = -100)  
    outs("\nopenat_test=");
    fd = sc3(57, -100, (long)"/proc/version", 0, 0);
    if (fd >= 0) {
        outs("ok\n");
        long n = sc3(63, fd, (long)buf, 127);
        sc1(57, fd);
        if (n > 0) { buf[n] = 0; outs(buf); }
    } else {
        outs("err:");
        long val = fd;
        char tmp[16]; int p = 0;
        if (val < 0) { tmp[p++] = '-'; val = -val; }
        if (val == 0) tmp[p++] = '0';
        else { char rev[16]; int rp = 0; while(val) { rev[rp++]='0'+(val%10); val/=10; } while(rp) tmp[p++]=rev[--rp]; }
        tmp[p]=0;
        outs(tmp);
        outs("\n");
    }
    
    outs("=== DONE ===\n");
    sc1(94, 0);
    for(;;);
}
