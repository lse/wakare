int main(int argc, char** argv)
{
    int count = 0;

    for(int i = 0; i < 256; i++) {
        count ^= i;
    }

    return count;
}
