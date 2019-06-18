__attribute__((noinline))
int mul(int a, int b)
{
    return a*b;
}

int main()
{
    return mul(12, 13);
}
