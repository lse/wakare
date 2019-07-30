#include <stdio.h>

int myprint(const char* str)
{
    return puts(str);
}

int main(int argc, char** argv)
{
    int (*myputs)(const char*) = myprint;

    for(int i = 0; i < 10; i++) {
        myputs("Hello World !\n");
    }

    return 0;
}
