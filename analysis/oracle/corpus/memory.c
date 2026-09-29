typedef struct Pair {
    int a;
    int b;
} Pair;

void copy_pair(Pair *dst, const Pair *src)
{
    *dst = *src;
}

int alias_mix(int *a, int *b)
{
    *a = *b + 1;
    *b += 2;
    return *a;
}
