#include <iostream>
#include <iomanip>
#include <random>

bool generateAES_KEY(unsigned char *pBuf, unsigned char nBufSize)
{
    unsigned char nCount = (nBufSize + sizeof(unsigned int) - 1) / sizeof(unsigned int);
    std::vector<unsigned int> v_r;
    for (auto i = 0; i < nCount; ++i)
    {
        std::random_device r;
        v_r.push_back(r());
    }
    std::memcpy(pBuf, v_r.data(), nBufSize);
    return false;
}

int main()
{
    // std::random_device r;
    // std::random_device r1;
    // std::cout << std::hex << r() << ',' << r1() << std::endl;
    unsigned char szBuf[32] = {0xDD};
    generateAES_KEY(szBuf, 32);
    for (auto sz : szBuf)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned short)sz << ' ';
    }
    std::cout << std::endl;
    return 0;
}