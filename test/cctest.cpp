#include <iostream>

class c_tool
{
};

class c_tool_extend : public c_tool
{
};

class c_a
{
private:
    int m_nVal;
    bool m_bVal;

public:
    static int m_st_val;
    c_tool *m_p_tool;
};

int c_a::m_st_val = 0xDD;

class c_b
{
public:
    c_a m_a;
};

class c_b_ex
{
public:
    c_b m_b;
};

int main()
{
    c_a::m_st_val = 1;
    c_b b1, b2;
    b1.m_a.m_st_val = 2;
    std::cout << "b2.m_a.m_st_val is :" << b2.m_a.m_st_val << std::endl;
    return 1;
}