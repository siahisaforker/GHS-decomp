class Pair {
public:
    Pair(int x, int y) : x_(x), y_(y) {}
    int sum() const { return x_ + y_; }

private:
    int x_;
    int y_;
};

extern "C" int cpp_inline_pair(int a, int b)
{
    Pair p(a, b);
    return p.sum();
}

