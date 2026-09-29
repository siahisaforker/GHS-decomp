struct Packedish {
    unsigned tag : 3;
    unsigned size : 13;
    int value;
};

unsigned struct_bits(const struct Packedish *p, unsigned x)
{
    return (p->tag << 24) | (p->size << 8) | ((unsigned)p->value & x);
}

