typedef struct TwoWords {
    unsigned a;
    unsigned b;
} TwoWords;

int nine_int_args(int a, int b, int c, int d, int e,
                  int f, int g, int h, int i)
{
    return a + b + c + d + e + f + g + h + i;
}

double mixed_args(int a, double b, float c, int d)
{
    return (double)a + b + (double)c + (double)d;
}

TwoWords return_struct(unsigned a, unsigned b)
{
    TwoWords value;
    value.a = a;
    value.b = b;
    return value;
}
