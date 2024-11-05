#include <iostream>
#include <string>
#include <memory>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>

static const unsigned int KEY_SIZE = 16;
static const unsigned int BLOCK_SIZE = 16;

// typedef unsigned char byte;

using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

void gen_params(unsigned char key[KEY_SIZE], unsigned char iv[BLOCK_SIZE])
{
  int rc = RAND_bytes(key, KEY_SIZE);
  if (rc != 1)
    throw std::runtime_error("RAND_bytes key failed");

  rc = RAND_bytes(iv, BLOCK_SIZE);
  if (rc != 1)
    throw std::runtime_error("RAND_bytes for iv failed");
}

int aes_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *pIn, unsigned int nInBufLen, unsigned char *pOut, unsigned int &nOutBufLen)
{
  unsigned int n = nInBufLen / 16;
  unsigned int m = nInBufLen % 16;
  if (m)
  {
    ++n;
  }
  int nNeedOutBufLen = n * BLOCK_SIZE;
  int nRt(-1);
  if (nOutBufLen < nNeedOutBufLen)
  {
    std::cout << "OutBufLen is too small." << std::endl;
    nRt = nNeedOutBufLen;
    nOutBufLen = 0;
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
        int out_len2 = nInBufLen + BLOCK_SIZE - nOutLen;
        rc = EVP_EncryptFinal_ex(ctx.get(), pOut + nOutLen, &out_len2);
        if (rc == 1)
        {
          nRt = nNeedOutBufLen;
          nOutBufLen = nOutLen + out_len2;
        }
      }
    }
  }
  return nRt;
}

#ifdef USING_STRING_AES_

void aes_encrypt(const unsigned char *key, const unsigned char *iv, const std::string &ptext, std::string &ctext)
{
  EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
  int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key, iv);
  if (rc != 1)
    throw std::runtime_error("EVP_EncryptInit_ex failed");

  // Recovered text expands upto BLOCK_SIZE
  ctext.resize(ptext.size() + BLOCK_SIZE);
  int out_len1 = (int)ctext.size();

  rc = EVP_EncryptUpdate(ctx.get(), (unsigned char *)ctext.data(), &out_len1, (const unsigned char *)ptext.data(), (int)ptext.size());
  if (rc != 1)
    throw std::runtime_error("EVP_EncryptUpdate failed");

  std::cout << "encrypt out_len1: " << out_len1 << std::endl;
  int out_len2 = (int)ctext.size() - out_len1;
  rc = EVP_EncryptFinal_ex(ctx.get(), (unsigned char *)ctext.data() + out_len1, &out_len2);
  if (rc != 1)
    throw std::runtime_error("EVP_EncryptFinal_ex failed");

  std::cout << "encrypt out_len2: " << out_len2 << std::endl;
  // Set cipher text size now that we know it
  ctext.resize(out_len1 + out_len2);
}

void aes_decrypt(const unsigned char *key, const unsigned char *iv, const std::string &ctext, std::string &rtext)
{
  EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
  int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key, iv);
  if (rc != 1)
    throw std::runtime_error("EVP_DecryptInit_ex failed");

  // Recovered text contracts upto BLOCK_SIZE
  rtext.resize(ctext.size());
  int out_len1 = (int)rtext.size();

  rc = EVP_DecryptUpdate(ctx.get(), (unsigned char *)rtext.data(), &out_len1, (const unsigned char *)ctext.data(), (int)ctext.size());
  if (rc != 1)
    throw std::runtime_error("EVP_DecryptUpdate failed");

  std::cout << "decrypt out_len1: " << out_len1 << std::endl;
  int out_len2 = (int)rtext.size() - out_len1;
  rc = EVP_DecryptFinal_ex(ctx.get(), (unsigned char *)rtext.data() + out_len1, &out_len2);
  if (rc != 1)
    throw std::runtime_error("EVP_DecryptFinal_ex failed");

  std::cout << "decrypt out_len2: " << out_len2 << std::endl;
  // Set recovered text size now that we know it
  rtext.resize(out_len1 + out_len2);
}

#endif

int aes_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *pData, unsigned int nDataLen, unsigned char *pOut, unsigned int &nOutDataLen)
{
  unsigned int n = nDataLen / 16;
  unsigned int m = nDataLen % 16;
  if (m)
  {
    ++n;
  }
  int nNeedOutBufLen = n * BLOCK_SIZE;
  int nRt(-1);
  if (nOutDataLen < nNeedOutBufLen)
  {
    std::cout << "OutBufLen is too small." << std::endl;
    nRt = nNeedOutBufLen;
    nOutDataLen = 0;
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
        nRt = nNeedOutBufLen;
      }
    }
  }
  return nRt;
}

int main(int argc, char *argv[])
{
  // Load the necessary cipher
  EVP_add_cipher(EVP_aes_128_cbc());

  // plaintext, ciphertext, recovered text
  unsigned char seqdata[] = {0x30, 0x35, 0x34, 0x30, 0x13, 0x51, 0x37, 0x34, 0x37, 0x00, 0x24, 0x00};

  unsigned char key[KEY_SIZE], iv[BLOCK_SIZE];
  gen_params(key, iv);
  std::cout << "Key is: " << std::endl;
  for (auto &&byteval : key)
  {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)byteval << " ";
  }
  std::cout << std::endl;

  std::cout << "IV is: " << std::endl;
  for (auto &&byteval : iv)
  {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)byteval << " ";
  }
  std::cout << std::dec << std::endl;

#ifdef USING_STRING_AES_
  std::string ptext((const char *)seqdata, sizeof(seqdata));
  std::string ctext, rtext;

  std::cout << "Original message:\n"
            << ptext << std::endl;

  aes_encrypt(key, iv, ptext, ctext);
  std::cout << "After AES, is: ";
  for (auto &&byteval : ctext)
  {
    unsigned char v = (unsigned char)byteval;
    std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)v << " ";
  }
  std::cout << std::dec << std::endl;
  std::cout << "data length is : " << ctext.length() << std::endl;

  aes_decrypt(key, iv, ctext, rtext);

  std::cout << "Recovered message:\n"
            << rtext << std::endl;
#else
  std::cout << "Original message: " << std::endl;
  for (int i = 0; i < sizeof(seqdata); ++i)
  {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)seqdata[i] << " ";
  }
  std::cout << std::dec << std::endl;
  unsigned char out[256] = {0};
  unsigned int nOutBufLen = sizeof(out);
  int nVal = aes_encrypt(key, iv, seqdata, sizeof(seqdata), out, nOutBufLen);
  if (nVal && nOutBufLen == nVal)
  {
    std::cout << "After AES encrypt is: " << std::endl;
    for (int i = 0; i < nVal; ++i)
    {
      std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)out[i] << " ";
    }
    std::cout << std::dec << std::endl;
    std::cout << "data length is : " << nOutBufLen << std::endl;

    unsigned char szDeOut[256] = {0};
    unsigned int nDeOutLen = sizeof(szDeOut);
    int nRt = aes_decrypt(key, iv, out, nOutBufLen, szDeOut, nDeOutLen);
    if (nRt && nDeOutLen)
    {
      std::cout << "After AES decrypt is: " << std::endl;
      for (int i = 0; i < nDeOutLen; ++i)
      {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (short)szDeOut[i] << " ";
      }
      std::cout << std::dec << std::endl;
    }
  }
#endif

  OPENSSL_cleanse(key, KEY_SIZE);
  OPENSSL_cleanse(iv, BLOCK_SIZE);
  return 0;
}

//  cl aes_tool.cpp /EHsc /std:c++20 -I "C:\\Program Files\\OpenSSL\\include"  D:\openssl\libcrypto.lib