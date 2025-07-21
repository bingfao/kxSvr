
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <iostream>
#include <fstream>

void GenerateKeysForEvp(EVP_PKEY *pkey, std::string &pri_key, std::string &pub_key)
{
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_PrivateKey(pri, pkey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_PUBKEY(pub, pkey);

    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    pri_key.resize(pri_len);
    pub_key.resize(pub_len);
    BIO_read(pri, &pri_key[0], pri_len);
    BIO_read(pub, &pub_key[0], pub_len);

    // 内存释放
    BIO_free_all(pub);
    BIO_free_all(pri);
}

// 生成 RSA 公私密钥对，然后交换分发，

int main()
{
    EVP_PKEY *pkey = EVP_RSA_gen(2048); // Generate a 2048-bit RSA key
    if (!pkey)
    {
        // Handle error, e.g., print OpenSSL error stack
        std::cerr << "Unable to gen pkey." << std::endl;
        return 1;
    }
    std::string pri_key;
    std::string pub_key;
    GenerateKeysForEvp(pkey, pri_key, pub_key);
    std::cout << "private key: \n"
              << pri_key << std::endl;
    std::cout << "public key: \n"
              << pub_key << std::endl;
    std::ofstream of_file("./pub_key.pem");
    if (of_file)
    {
        of_file << pub_key << std::endl;
        of_file.close();
    }
    of_file.open("./pri_key.pem");
    if (of_file)
    {
        of_file << pri_key << std::endl;
        of_file.close();
    }

    // FILE *fp = fopen("rsa_public_key.pem", "wb+");
    // if (fp)
    // {
    //     PEM_write_PUBKEY(fp, pkey); // 这里会直接异常退出
    //     fclose(fp);
    // }
    // else
    // {
    //     PEM_write_PUBKEY(stdout, pkey); // Write public key to stdout
    // }
    // fp = fopen("rsa_private_key.pem", "wb+");
    // if (fp)
    // {
    //     PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    //     fclose(fp);
    // }
    // else
    // {
    //     PEM_write_PrivateKey(stdout, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    // }
    EVP_PKEY_free(pkey); // Free the key
    return 0;
}

// cl rsa_demo.cpp /EHsc /std:c++20  -D_WIN32 -I "C:\\Program Files\\OpenSSL\\include"   D:\openssl\libcrypto.lib