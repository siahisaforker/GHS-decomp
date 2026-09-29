typedef struct Flags {
    unsigned a : 3;
    unsigned b : 5;
    unsigned c : 8;
    signed d : 6;
} Flags;

unsigned read_b(Flags value)
{
    return value.b;
}

void write_c(Flags *value, unsigned x)
{
    value->c = x;
}

int read_signed_d(Flags value)
{
    return value.d;
}
