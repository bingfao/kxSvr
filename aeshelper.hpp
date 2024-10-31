
#pragma once

#ifndef _KX_AES_HELPER_HPP_
#define _KX_AES_HELPER_HPP_


const unsigned int AES_BLOCK_SIZE = 16;


/// @brief    随机生成IV
/// @param piv 指向一块大小为AES_BLOCK_SIZE的内存
/// @return   成功或失败
bool Rand_IV_Data(unsigned char* piv);

/// @brief AES-128-CBC 加密
/// @param key 16Byte
/// @param iv  16Byte
/// @param pIn 原始数据地址
/// @param nInBufLen 原始数据长度
/// @param pOut 加密后的数据地址
/// @param nOutBufLen nOutBufLen为加密后的数据长度
/// @return 成功或失败
bool aes_128_CBC_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *pIn, unsigned int nInBufLen,
                unsigned char *pOut, unsigned int &nOutBufLen);


/// @brief AES-128-CBC 解密
/// @param key 16Byte
/// @param iv  16Byte
/// @param pData 要解密的数据地址
/// @param nDataLen 要解密的数据长度
/// @param pOut 解密后的数据地址
/// @param nOutDataLen 成功解密时，nOutBufLen为解密后的数据长度，失败时，为需要的bufLen
/// @return 成功或失败
bool aes_128_CBC_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *pData, unsigned int nDataLen,
                unsigned char *pOut, unsigned int &nOutDataLen);

#endif