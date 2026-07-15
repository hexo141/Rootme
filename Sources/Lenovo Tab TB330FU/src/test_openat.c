void _start() {
    // openat(AT_FDCWD, "/proc/version", O_RDONLY)
    long fd;
    register long x8 asm("x8") = 57; // SYS_openat
    register long x0 asm("x0") = -100; // AT_FDCWD
    register long x1 asm("x1") = (long)"/proc/version";
    register long x2 asm("x2") = 0; // O_RDONLY
    asm volatile("svc #0" : "=r"(fd) : "r"(x0), "r"(x1), "r"(x2), "r"(x8) : "memory");
    
    // Write fd number to stdout
    char buf[32];
    int i = 30;
    buf[31] = 0;
    if (fd == 0) buf[i--] = '0';
    else {
        long n = fd;
        if (n < 0) { buf[i--] = '-'; n = -n; }
        while (n > 0) { buf[i--] = '0' + (n % 10); n /= 10; }
    }
    buf[i] = ':';
    
    // write(1, buf+i, ...)
    long written;
    register long wx8 asm("x8") = 64; // SYS_write
    register long wx0 asm("x0") = 1;
    register long wx1 asm("x1") = (long)(buf + i);
    register long wx2 asm("x2") = 31 - i;
    asm volatile("svc #0" : "=r"(written) : "r"(wx0), "r"(wx1), "r"(wx2), "r"(wx8) : "memory");
    
    if (fd >= 0) {
        // read from fd
        char rbuf[512];
        long n;
        register long rx8 asm("x8") = 63; // SYS_read
        register long rx0 asm("x0") = fd;
        register long rx1 asm("x1") = (long)rbuf;
        register long rx2 asm("x2") = 511;
        asm volatile("svc #0" : "=r"(n) : "r"(rx0), "r"(rx1), "r"(rx2), "r"(rx8) : "memory");
        
        if (n > 0) {
            rbuf[n] = '\n';
            register long w2x8 asm("x8") = 64;
            register long w2x0 asm("x0") = 1;
            register long w2x1 asm("x1") = (long)rbuf;
            register long w2x2 asm("x2") = n;
            asm volatile("svc #0" :: "r"(w2x0), "r"(w2x1), "r"(w2x2), "r"(w2x8) : "memory");
        }
        
        // close(fd)
        register long cx8 asm("x8") = 57;
        register long cx0 asm("x0") = fd;
        asm volatile("svc #0" :: "r"(cx0), "r"(cx8) : "memory");
    }
    
    // exit(0)
    register long ex8 asm("x8") = 93;
    register long ex0 asm("x0") = 0;
    asm volatile("svc #0" :: "r"(ex0), "r"(ex8) : "memory");
}
