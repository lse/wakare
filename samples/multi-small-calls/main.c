#include <stdio.h>

int cond_ret(int input)
{
    if(input % 2 == 0) {
        return input ^ 0xfefefefe;
    }

    return input ^ 0x41414141;
}

int main()
{
    int v = cond_ret(42);
    int c = cond_ret(53);
    int acc = 0;

    for(int i = v*c; i < (v*c)+4; i++) {
        acc += cond_ret(i);
    }

    return 0;
}
