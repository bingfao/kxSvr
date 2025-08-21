
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>

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

bool RSA_encrypt(const unsigned char *pData, size_t nDataLen, const std::string &str_pub_key, std::string &str_enc_out)
{
    bool brt(false);
    EVP_PKEY_CTX *ctx = 0;
    BIO *keybio = BIO_new_mem_buf(str_pub_key.c_str(), -1);
    if (keybio)
    {
        EVP_PKEY *pKey = PEM_read_bio_PUBKEY(keybio, 0, NULL, NULL);
        if (pKey)
        {
            ctx = EVP_PKEY_CTX_new(pKey, NULL);
            if (ctx && EVP_PKEY_encrypt_init(ctx) > 0)
            {
                // const int key_len = EVP_PKEY_size(pKey);
                // unsigned char *pBuf = new unsigned char[key_len];
                // if (pBuf)
                
                // {
                //     const unsigned char *pDataEnd = pData + nDataLen;
                //     const int block_len = key_len - 11;
                //     int len = block_len;
                //     const size_t reserve_size = ((nDataLen / block_len + ((nDataLen % block_len == 0) ? 0 : 1)) * key_len);
                //     str_enc_out.reserve(reserve_size);
                //     unsigned char *ptr = const_cast<unsigned char *>(pData);
                //     while (ptr < pDataEnd)
                //     {
                //         if ((ptr + len) > pDataEnd)
                //             len = pDataEnd - ptr;

                //         size_t outl = block_len;
                //         int ret = EVP_PKEY_encrypt(ctx, pBuf, &outl, ptr, len);
                //         if (ret > 0)
                //         {
                //             str_enc_out.append(reinterpret_cast<const char *>(pBuf), outl);
                //         }
                //         ptr += len;
                //     }
                //     delete[] pBuf;
                //     pBuf = nullptr;
                // }
                if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0)
                {
                    size_t outlen = 0;
                    /* Determine buffer length */
                    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, pData, nDataLen) > 0)
                    {
                        auto out = OPENSSL_malloc(outlen);
                        if (out)
                        {
                            unsigned char *pOutBuf = reinterpret_cast<unsigned char *>(out);
                            if (EVP_PKEY_encrypt(ctx, pOutBuf, &outlen, pData, nDataLen) > 0)
                            {
                                str_enc_out.erase();
                                str_enc_out.append(reinterpret_cast<char *>(pOutBuf), outlen);
                                brt = true;
                            }
                        }
                        OPENSSL_free(out);
                    }
                }
                EVP_PKEY_CTX_free(ctx);
            }
            EVP_PKEY_free(pKey);
        }
        BIO_free(keybio);
    }
    return brt;
}

bool RSA_decrypt(const unsigned char *pData, size_t nDataLen, const std::string &str_pri_key, std::string &str_dec_out)
{
    bool brt(false);
    EVP_PKEY_CTX *ctx = 0;
    BIO *keybio = BIO_new_mem_buf(str_pri_key.c_str(), -1);
    if (keybio)
    {
        EVP_PKEY *pKey = PEM_read_bio_PrivateKey(keybio, 0, NULL, NULL);
        if (pKey)
        {
            ctx = EVP_PKEY_CTX_new(pKey, NULL);
            if (ctx && EVP_PKEY_decrypt_init(ctx) > 0)
            {
                if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0)
                {
                    size_t outlen = 0;
                    /* Determine buffer length */
                    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, pData, nDataLen) > 0)
                    {
                        auto out = OPENSSL_malloc(outlen);
                        if (out)
                        {
                            unsigned char *pOutBuf = reinterpret_cast<unsigned char *>(out);
                            if (EVP_PKEY_decrypt(ctx, pOutBuf, &outlen, pData, nDataLen) > 0)
                            {
                                str_dec_out.erase();
                                str_dec_out.append(reinterpret_cast<char *>(pOutBuf), outlen);
                                brt = true;
                            }
                        }
                        OPENSSL_free(out);
                    }
                }
                EVP_PKEY_CTX_free(ctx);
            }
            EVP_PKEY_free(pKey);
        }
        BIO_free(keybio);
    }
    return brt;
}

bool generateRSAKeyPair()
{
    bool brt(false);
    EVP_PKEY *pkey = EVP_RSA_gen(2048); // Generate a 2048-bit RSA key
    if (!pkey)
    {
        // Handle error, e.g., print OpenSSL error stack
        std::cerr << "Unable to gen pkey." << std::endl;
    }
    else
    {
        std::string pri_key;
        std::string pub_key;
        GenerateKeysForEvp(pkey, pri_key, pub_key);
        EVP_PKEY_free(pkey); // Free the key
        brt = true;
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
    }
    return brt;
}

int main()
{
    std::ifstream if_file("./pub_key.pem");
    if (if_file)
    {
        std::string str_pub_key;
        str_pub_key.assign(std::istreambuf_iterator<char>(if_file),
                           std::istreambuf_iterator<char>());
        // std::cout << "pub_key is:\n"
        //           << str_pub_key << std::endl;
        if_file.close();
        const char *szText = "Hello World, RSA!  \n1234567890\n928272625242321\n";
        const unsigned char *pText = reinterpret_cast<const unsigned char *>(szText);
        size_t nTextLen = strlen(szText);
        std::string str_enc_out = "no value";
        if (RSA_encrypt(pText, nTextLen, str_pub_key, str_enc_out))
        {
            std::cout << "RSA_encrypt result:" << std::endl;
            auto outlen = str_enc_out.length();
            const unsigned char *pEnc_data = reinterpret_cast<const unsigned char *>(str_enc_out.c_str());
            size_t base64_len = (outlen + 2) / 3 * 4;
            if (base64_len)
            {
                std::string ret;
                ret.resize(base64_len);
                
                EVP_EncodeBlock((unsigned char *)ret.data(), pEnc_data, outlen);
                std::cout << ret << std::endl;
            }
            std::ifstream in_private_file("./pri_key.pem");
            if (in_private_file)
            {
                std::string str_pri_key;
                str_pri_key.assign(std::istreambuf_iterator<char>(in_private_file),
                                   std::istreambuf_iterator<char>());
                // std::cout << "pri_key is:\n"
                //           << str_pri_key << std::endl;
                in_private_file.close();
                std::string str_decrypt_out;
                if(RSA_decrypt(pEnc_data,outlen,str_pri_key,str_decrypt_out))
                {
                    std::cout<<"RSA_decrypt result:"<<str_decrypt_out<<std::endl;
                }
            }
            
        }
    }
    return 0;
}

// cl rsa_demo.cpp /EHsc /std:c++20  -D_WIN32 -I "C:\\Program Files\\OpenSSL\\include"   D:\openssl\libcrypto.lib