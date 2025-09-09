#include <openssl/evp.h>
#include <openssl/kdf.h>
//#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
//#include <openssl/err.h>
#include <cassert>
#include <cstring>
#include <iostream>

void error(std::string error_type)
{
    std::cout << error_type << '\n';
}




int main()
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    unsigned char out[64];
    OSSL_PARAM params[6], *p = params;

    kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                             (void*)"password", (size_t)8);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             (void*)"NaCl", (size_t)4);
    uint64_t n=1024;
    uint32_t r=8;
    uint32_t pv=16;
    *p++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &pv);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) <= 0)
    {
        error("EVP_KDF_derive");
    }
    else{
        std::cout<<"script ok"<<std::endl;
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
        
        assert(!memcmp(out, expected, sizeof(out)));
    }

    EVP_KDF_CTX_free(kctx);
}

//  cl script_test.cpp /EHsc /std:c++20 -I "C:\\Program Files\\OpenSSL\\include"  D:\openssl\libcrypto.lib