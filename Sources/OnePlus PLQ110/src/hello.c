// hello.c: NDK cross-compile sanity check for the OnePlus PLQ110 toolchain
#include <stdio.h>
int main(void) {
    printf("[*] hello from OnePlus PLQ110 toolchain\n");
    printf("[*] target: aarch64-linux-android\n");
    printf("[*] sizeof(void*) = %zu\n", sizeof(void*));
    printf("[*] sizeof(long)  = %zu\n", sizeof(long));
    return 0;
}
