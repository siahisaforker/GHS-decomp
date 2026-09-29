int sum_n(const int *p, int n)
{
    int sum = 0;
    int i;
    for (i = 0; i < n; ++i)
        sum += p[i];
    return sum;
}

int sum_eight(const int *p)
{
    int sum = 0;
    int i;
    for (i = 0; i < 8; ++i)
        sum += p[i];
    return sum;
}
