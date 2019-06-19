int main(int argc, char** argv)
{
    int acc = 0;

    for(int i = 0; i < 64; i++) {
        acc += 0x42424242;

        for(int j = 0; j < 64; j++) {
            acc ^= 0x73737373;

            for(int k = 0; k < 64; k++) {
                acc = ((acc & 0xffff) << 16) | ((acc >> 16) & 0xffff);
                acc ^= 0xdeadbeef;
            }
        }
    }

    return acc;
}
