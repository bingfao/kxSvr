#include <iostream>
#include "aeshelper.hpp"
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>

using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

bool Rand_IV_Data(unsigned char *piv)
{
	int rc = RAND_bytes(piv, AES_BLOCK_SIZE);
	return rc == 1;
}

bool aes_128_CBC_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *pIn, unsigned int nInBufLen, unsigned char *pOut, unsigned int &nOutBufLen)
{
	unsigned int n = nInBufLen / 16;
	unsigned int m = nInBufLen % 16;
	if (m)
	{
		++n;
	}
	int nNeedOutBufLen = n * AES_BLOCK_SIZE;
	bool brt(false);
	if (nOutBufLen < nNeedOutBufLen)
	{
		std::cout << "OutBufLen is too small." << std::endl;
		nOutBufLen = nNeedOutBufLen;
	}
	else
	{
		EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
		int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key, iv);
		if (rc == 1)
		{
			int nOutLen = nOutBufLen;
			rc = EVP_EncryptUpdate(ctx.get(), pOut, (int *)&nOutLen, pIn, nInBufLen);
			if (rc == 1)
			{
				int out_len2 = nInBufLen + AES_BLOCK_SIZE - nOutLen;
				rc = EVP_EncryptFinal_ex(ctx.get(), pOut + nOutLen, &out_len2);
				if (rc == 1)
				{
					nOutBufLen = nOutLen + out_len2;
					brt = true;
				}
			}
		}
	}
	return brt;
}

bool aes_128_CBC_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *pData, unsigned int nDataLen, unsigned char *pOut, unsigned int &nOutDataLen)
{
	unsigned int n = nDataLen / 16;
	unsigned int m = nDataLen % 16;
	if (m)
	{
		++n;
	}
	int nNeedOutBufLen = n * AES_BLOCK_SIZE;
	bool brt(false);
	if (nOutDataLen < nNeedOutBufLen)
	{
		std::cout << "OutBufLen is too small." << std::endl;
		nOutDataLen = nNeedOutBufLen;
	}
	EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key, iv);
	if (rc == 1)
	{
		int out_len1 = nOutDataLen;
		rc = EVP_DecryptUpdate(ctx.get(), (unsigned char *)pOut, &out_len1, (const unsigned char *)pData, nDataLen);
		if (rc == 1)
		{
			int out_len2 = nOutDataLen - out_len1;
			rc = EVP_DecryptFinal_ex(ctx.get(), pOut + out_len1, &out_len2);
			if (rc == 1)
			{
				nOutDataLen = out_len1 + out_len2;
				brt = true;
			}
		}
	}
	return brt;
}