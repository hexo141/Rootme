void _start() {
    char *path = "/proc/version";
    long fd;
    
    // Test 1: SYS_open (56)
    asm volatile(
        "mov x8, #56\n"
        "mov x0, %1\n"
        "mov x1, #0\n"  // O_RDONLY
        "svc #0\n"
        "mov %0, x0\n"
        : "=r"(fd) : "r"(path) : "x0", "x1", "x8"
    );
    
    // Write fd
    char buf[64];
    int len = 0;
    long n = fd;
    if (n < 0) { buf[len++] = '-'; n = -n; }
    if (n == 0) buf[len++] = '0';
    else {
        char rev[16]; int rp = 0;
        while (n > 0) { rev[rp++] = '0' + (n % 10); n /= 10; }
        while (rp > 0) buf[len++] = rev[--rp];
    }
    buf[len++] = '\n';
    
    asm volatile(
        "mov x8, #64\n"
        "mov x0, #1\n"
        "mov x1, %0\n"
        "mov x2, %1\n"
        "svc #0\n"
        :: "r"(buf), "r"(len) : "x0", "x1", "x2", "x8"
    );
    
    if (fd >= 0) {
        // Read and print
        char rbuf[256];
        asm volatile(
            "mov x8, #63\n"
            "mov x0, %0\n"
            "mov x1, %1\n"
            "mov x2, #255\n"
            "svc #0\n"
            "mov %0, x0\n"
            : "+r"(fd), "=r"(rbuf) : : "x0", "x1", "x2", "x8"
        );
        if (fd > 0) {
            rbuf[fd] = 0;
            asm volatile(
                "mov x8, #64\n"
                "mov x0, #1\n"
                "mov x1, %0\n"
                "mov x2, %1\n"
                "svc #0\n"
                :: "r"(rbuf), "r"(fd) : "x0", "x1", "x2", "x8"
            );
        }
        // close
        asm volatile("mov x8, #57; mov x0, %0; svc #0" :: "r"(fd) : "x0", "x8");
    }
    
    // exit
    asm volatile("mov x8, #94; mov x0, #0; svc #0");
}
