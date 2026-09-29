int loop_switch(const int *p, int n, int mode)
{
    int sum = 0;
    int i;

    for (i = 0; i < n; ++i) {
        if (p[i] > 3)
            sum += p[i];
    }

    switch (mode) {
    case 0: return sum;
    case 2: return sum + n;
    case 7: return sum - n;
    default: return -1;
    }
}

