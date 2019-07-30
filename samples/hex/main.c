#include <stdio.h>
#include <string.h>

unsigned char extract_low_nibble(unsigned char input)
{
    return input & 0x0f;
}

unsigned char extract_high_nibble(unsigned char input)
{
    return (input >> 4) & 0xf;
}

void bytes_to_hexstr(unsigned char* input, unsigned char* output, int size)
{
    char* charset = "0123456789abcdef";

    for(int i = 0; i < size; i++) {
        output[2*i] = charset[extract_high_nibble(input[i])];
        output[(2*i)+1] = charset[extract_low_nibble(input[i])];
    }
}

int main(int argc, char** argv)
{
    unsigned char input[] = {0x41, 0x42, 0x43, 0x44};
    unsigned char output[8] = {0};

    bytes_to_hexstr(input, output, 4);

    for(int i = 0; i < 4; i++) {
        printf("%c%c", output[2*i], output[(2*i)+1]);
    }

    printf("\n");

    return 0;
}
