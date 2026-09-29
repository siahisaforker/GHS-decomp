struct Base {
    virtual int eval(int x);
};

int call_virtual(Base *base, int x)
{
    return base->eval(x) + 1;
}

struct Small {
    int value;
    Small(int v) : value(v) {}
    int add(int x) const { return value + x; }
};

int construct_small(int x)
{
    Small s(x);
    return s.add(3);
}
