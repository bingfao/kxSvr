#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <openssl/err.h>

void error(std::string error_type)
{
    std::cout << error_type << '\n';
}

void printBN_32B(BIGNUM *pBN_Lx, const char *szName)
{
    unsigned char sz_buf[64] = {0};
    BN_bn2bin(pBN_Lx, sz_buf);
    std::cout << szName << " is: " << std::endl;
    for (auto &&i : sz_buf)
    {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)i << ' ';
    }
    std::cout << std::endl;
}

void test()
{
    EVP_PKEY_CTX *pctx;
    unsigned char out[64];

    size_t outlen = sizeof(out);
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);
    const char *szPsw = "password";
    const unsigned char szSalt[] = "NaCl";
    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        error("EVP_PKEY_derive_init");
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, szPsw, strlen(szPsw)) <= 0)
    {
        error("EVP_PKEY_CTX_set1_pbe_pass");
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, szSalt, strlen((char *)szSalt)) <= 0)
    {
        error("EVP_PKEY_CTX_set1_scrypt_salt");
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, 1024) <= 0)
    {
        error("EVP_PKEY_CTX_set_scrypt_N");
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, 8) <= 0)
    {
        error("EVP_PKEY_CTX_set_scrypt_r");
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, 16) <= 0)
    {
        error("EVP_PKEY_CTX_set_scrypt_p");
    }
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0)
    {
        error("EVP_PKEY_derive");
    }
    else
    {
        std::cout << "script ok" << std::endl;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
            0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
            0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
            0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
            0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
            0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
            0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
            0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40};
        if (memcmp(out, expected, sizeof(out)))
        {
            error("out not expected.");
        }
        else
        {
            std::cout << "out is expected." << std::endl;
        }
        // assert(!memcmp(out, expected, sizeof(out)));
    }

    EVP_PKEY_CTX_free(pctx);
}

int main()
{
    EVP_PKEY_CTX *pctx = nullptr;
    unsigned char out[80] = {0};

    size_t outlen = sizeof(out);
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);
    const char *szPsw = "17998807";
    const unsigned char szSalt[] = "tuyuexin";
    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        error("EVP_PKEY_derive_init");
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, szPsw, strlen(szPsw)) <= 0)
    {
        error("EVP_PKEY_CTX_set1_pbe_pass");
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, szSalt, strlen((char *)szSalt)) <= 0)
    {
        error("EVP_PKEY_CTX_set1_scrypt_salt");
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, 4096) <= 0)
    {
        error("EVP_PKEY_CTX_set_scrypt_N");
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, 8) <= 0)
    {
        error("EVP_PKEY_CTX_set_scrypt_r");
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, 1) <= 0)
    {
        error("EVP_PKEY_CTX_set_scrypt_p");
    }
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0)
    {
        error("EVP_PKEY_derive");
    }
    else
    {
        std::cout << "script ok,outbuf len is: " << outlen << std::endl;
        for (auto &&i : out)
        {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)i << ' ';
        }
        std::cout << std::endl;
    }

    const char *szValZ0 = "6408161bbc64a41827cf072c62efdae535739e513ad3050e66a9f53eb69c15bb3c22010acb5f7f02"; // 不能带前缀0x
    const char *szValZ1 = "dd008ce70d974431369ef8e569dee33977fa9fd2e13a55c8c80c244a05559264b0498c1f5216f327";
    const char *szValN = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    unsigned char uValN_Arr[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

    
    BN_CTX *pBN_Ctx = BN_CTX_new();
    if (pBN_Ctx)
    {
        BIGNUM *pBN_N = nullptr;
        // BIGNUM *pBN_N = BN_new();
        if (BN_hex2bn(&pBN_N, szValN))
        {
            if (pBN_N)
            {
                BN_sub_word(pBN_N, 1);
                // BIGNUM *pBN_Z0 = nullptr;
                // if (BN_hex2bn(&pBN_Z0, szValZ0))
                BIGNUM *pBN_Z0 =  BN_new();
                BN_bin2bn(out,40,pBN_Z0);
                {
                    if (pBN_Z0)
                    {
                        BIGNUM *pBN_W0 = BN_new();
                        if (1 == BN_mod(pBN_W0, pBN_Z0, pBN_N, pBN_Ctx))
                        {
                            BN_add_word(pBN_W0, 1);
                            unsigned char szW0[32] = {0};
                            if (pBN_W0)
                            {
                                BN_bn2bin(pBN_W0, szW0);
                                std::cout << "W0 is: " << std::endl;
                                for (auto &&i : szW0)
                                {
                                    std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)i << ' ';
                                }
                                std::cout << std::endl;

                                BN_free(pBN_W0);
                                pBN_W0 = nullptr;
                            }
                        }
                        else
                        {
                            auto err_i = ERR_get_error();
                            char sz_errinfo[256] = {0};
                            ERR_error_string(err_i, sz_errinfo);
                            std::cout << "err is: " << sz_errinfo << std::endl;
                        }

                        BN_free(pBN_Z0);
                        pBN_Z0 = nullptr;
                    }
                }
                // BIGNUM *pBN_Z1 = nullptr;
                // if (BN_hex2bn(&pBN_Z1, szValZ1))
                BIGNUM *pBN_Z1 = BN_new();
                BN_bin2bn(out+40,40,pBN_Z1);
                {
                    if (pBN_Z1)
                    {
                        BIGNUM *pBN_W1 = BN_new();
                        if (1 == BN_mod(pBN_W1, pBN_Z1, pBN_N, pBN_Ctx))
                        {
                            BN_add_word(pBN_W1, 1);
                            // unsigned char szW1[32] = {0};
                            if (pBN_W1)
                            {
                                printBN_32B(pBN_W1, "W1");
                                // BN_bn2bin(pBN_W1, szW1);
                                // std::cout << "W1 is: " << std::endl;
                                // for (auto &&i : szW1)
                                // {
                                //     std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)i << ' ';
                                // }
                                // std::cout << std::endl;

                                const char *szValGx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"; // 不能带前缀0x
                                const char *szValGy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
                                const char *szVal_a = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
                                const char *szVal_b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
                                const char *szVal_p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
                                //const char *szVal_N = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
                                BIGNUM *pBN_Gx = nullptr;
                                BIGNUM *pBN_Gy = nullptr;
                                BIGNUM *pBN_a = nullptr;
                                BIGNUM *pBN_b = nullptr;
                                BIGNUM *pBN_p = nullptr;
                                //BIGNUM *pBN_N = nullptr;
                                BN_hex2bn(&pBN_Gx, szValGx);
                                BN_hex2bn(&pBN_Gy, szValGy);
                                BN_hex2bn(&pBN_a, szVal_a);
                                BN_hex2bn(&pBN_b, szVal_b);
                                BN_hex2bn(&pBN_p, szVal_p);
                               //BN_hex2bn(&pBN_N, szVal_N);
                                // BIGNUM *pBN_ap = BN_new();
                                // BIGNUM *pBN_bp = BN_new();
                                // BN_mod(pBN_ap,pBN_a,pBN_p,pBN_Ctx);
                                // BN_mod(pBN_bp,pBN_b,pBN_p,pBN_Ctx);

                                BIGNUM *pBN_h = BN_new();
                                BN_set_word(pBN_h, 1);

                                EC_GROUP *pEC_Group = EC_GROUP_new_curve_GFp(pBN_p, pBN_a, pBN_b, pBN_Ctx);
                                if (pEC_Group)
                                {
                                    EC_POINT *pEC_ptG = EC_POINT_new(pEC_Group);
                                    if (pEC_ptG)
                                    {
                                        EC_POINT_set_affine_coordinates_GFp(pEC_Group, pEC_ptG, pBN_Gx, pBN_Gy, pBN_Ctx);
                                        EC_POINT *pEC_ptR = EC_POINT_new(pEC_Group);

                                        if (pEC_ptR && EC_POINT_mul(pEC_Group, pEC_ptR, nullptr, pEC_ptG, pBN_W1, pBN_Ctx))
                                        {
                                            std::cout << "L is: " << EC_POINT_point2hex(pEC_Group, pEC_ptR, POINT_CONVERSION_UNCOMPRESSED, pBN_Ctx) << std::endl;
                                            EC_POINT_free(pEC_ptR);
                                        }
                                    }
                                    EC_GROUP_free(pEC_Group);
                                }
                                // if (BN_hex2bn(&pBN_Gx, szValGx) && BN_hex2bn(&pBN_Gy, szValGy))
                                // {
                                //     printBN_32B(pBN_Gx, "Gx");
                                //     printBN_32B(pBN_Gy, "Gy");
                                //     BIGNUM *pBN_Lx = BN_new();
                                //     BIGNUM *pBN_Ly = BN_new();
                                //     if (BN_mul(pBN_Lx, pBN_W1, pBN_Gx, pBN_Ctx))
                                //     {
                                //         printBN_32B(pBN_Lx, "Lx");
                                //         BN_free(pBN_Lx);
                                //     }
                                //     if (BN_mul(pBN_Ly, pBN_W1, pBN_Gy, pBN_Ctx) && BN_mul_word(pBN_Ly,2))
                                //     {
                                //         printBN_32B(pBN_Ly, "Ly");
                                //         BN_free(pBN_Ly);
                                //         // unsigned char sz_buf[32] = {0};
                                //         // BN_bn2bin(pBN_Ly, sz_buf);
                                //         // std::cout << "Ly is: " << std::endl;
                                //         // for (auto &&i : sz_buf)
                                //         // {
                                //         //     std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)i << ' ';
                                //         // }
                                //         // std::cout << std::endl;
                                //     }
                                //}

                                BN_free(pBN_W1);
                                pBN_W1 = nullptr;
                            }
                        }
                        else
                        {
                            auto err_i = ERR_get_error();
                            char sz_errinfo[256] = {0};
                            ERR_error_string(err_i, sz_errinfo);
                            std::cout << "err is: " << sz_errinfo << std::endl;
                        }
                        BN_free(pBN_Z1);
                        pBN_Z1 = nullptr;
                    }
                }
                //}
                BN_free(pBN_N);
                pBN_N = nullptr;
            }
        }

        BN_CTX_free(pBN_Ctx);
    }
    EVP_PKEY_CTX_free(pctx);
}

//  cl script_test2.cpp /EHsc /std:c++20 -I "C:\\Program Files\\OpenSSL\\include"  D:\openssl\libcrypto.lib