void add8(float *dst, const float *a, const float *b)
{
    int i;
    for (i = 0; i < 8; ++i)
        dst[i] = a[i] + b[i];
}

void madd8(float *dst, const float *a, const float *b, const float *c)
{
    int i;
    for (i = 0; i < 8; ++i)
        dst[i] = a[i] * b[i] + c[i];
}

float dot8(const float *a, const float *b)
{
    float sum = 0.0f;
    int i;
    for (i = 0; i < 8; ++i)
        sum += a[i] * b[i];
    return sum;
}
