extern int global_i;
extern volatile unsigned global_v;

int sign_char(signed char x)
{
    return x;
}

unsigned zero_char(unsigned char x)
{
    return x;
}

int sign_short(short x)
{
    return x;
}

unsigned zero_short(unsigned short x)
{
    return x;
}

int load_global(void)
{
    return global_i + 1;
}

void store_global(int x)
{
    global_i = x;
}

unsigned volatile_roundtrip(unsigned x)
{
    global_v = x;
    return global_v;
}
