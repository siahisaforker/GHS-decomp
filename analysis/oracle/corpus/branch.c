int select_value(int x, int a, int b)
{
    if (x > 3)
        return a + 1;
    return b - 1;
}

int dense_switch(int x)
{
    switch (x) {
    case 0: return 7;
    case 1: return 11;
    case 2: return 19;
    case 3: return 23;
    default: return -1;
    }
}

int sparse_switch(int x)
{
    switch (x) {
    case 1: return 5;
    case 17: return 7;
    case 99: return 11;
    case 1000: return 13;
    default: return -1;
    }
}
