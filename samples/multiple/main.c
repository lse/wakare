#include <stdlib.h>

int moar_loops(int arg)
{
    int acc = 0xdeadbeef;

    for(int i = 0; i < 5; i++) {
        acc = (acc >> 16) | ((acc & 0xffff) << 16);
        acc ^= arg;
    }

    return acc;
}

int main(int argc, char** argv)
{
    if(argc != 1) {
        exit(-1);
    } else {
        int c = 0;

        for(int i = 0; i < 28; i++) {
            c ^= (i << 5) ^ (i >> 12);
            c = moar_loops(c);
        }
    }

    return 0;
}
