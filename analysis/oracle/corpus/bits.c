unsigned rotate7(unsigned x)
{
    return (x << 7) | (x >> 25);
}

unsigned extract_insert(unsigned x)
{
    return ((x >> 5) & 0x3fu) | ((x & 7u) << 8);
}
