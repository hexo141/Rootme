void _start() {
    // write(1, "OK\n", 3)
    asm volatile(
        "mov x0, #1\n"
        "ldr x1, =msg\n"
        "mov x2, #3\n"
        "mov x8, #64\n"
        "svc #0\n"
        // exit(42)
        "mov x0, #42\n"
        "mov x8, #93\n"
        "svc #0\n"
        "msg: .ascii \"OK\\n\"\n"
    );
}
