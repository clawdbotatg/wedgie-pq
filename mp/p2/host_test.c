// Checks p2.c's permutation against Plonky3's vectors on the computer: cc -DP2_HOST host_test.c
#include <stdio.h>
#include "p2.c"

int main(int argc, char **argv) {
    uint32_t s[16];
    for (int i = 0; i < 16; i++) {
        if (scanf("%u", &s[i]) != 1) return 2;
    }
    permute(s);
    for (int i = 0; i < 16; i++) printf("%u ", s[i]);
    printf("\n");
    return 0;
}
