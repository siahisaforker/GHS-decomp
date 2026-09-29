extern int sink_i(int, int, int, int, int, int, int, int, int, int);
extern double sink_f(double, double, double, double, double, double, double, double, double);

int ten_int_args(int a, int b, int c, int d, int e,
                 int f, int g, int h, int i, int j)
{
    return sink_i(a, b, c, d, e, f, g, h, i, j) + a + j;
}

double nine_fp_args(double a, double b, double c, double d, double e,
                    double f, double g, double h, double i)
{
    return sink_f(a, b, c, d, e, f, g, h, i) + a + i;
}

long long mixed_wide(int a, long long b, int c, long long d)
{
    return b + d + a + c;
}
