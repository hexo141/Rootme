// test_min.c: smallest possible PIE binary to verify NDK toolchain works
#include <unistd.h>
int main(void) {
    write(1, "[+] plq110 test_min ok\n", 23);
    return 0;
}
