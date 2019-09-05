/* rijndael.h */

/* This file is derived from ccrypt, which is free software
   and covered by the GNU general public license. */

#ifndef __RIJNDAEL_H
#define __RIJNDAEL_H

#include <cstdint>

enum ERijndaelBits
{
	ERijndaelBits128 = 128,
	ERijndaelBits192 = 192,
	ERijndaelBits256 = 256,
};

struct roundkey
{
public:
	roundkey(){};
	~roundkey(){};
public:
	bool isInit()
	{
		return (BC!=0 && KC!=0 && ROUNDS!=0);
	}
public:
    int BC = 0;
    int KC = 0;
    int ROUNDS = 0;
    int shift[2][4];
    uint32_t rk[120];
};


/*
 * @brief 初始化Rijndael密钥
 * 
 * @param handle 密钥句柄
 * @param key 密钥数组，长度必须和keyBits相同
 * @param keyBits 密钥长度128/192/256
 * @param blockBits 加密块大小128/192/256
 *
 * @return 0成功，非0失败 
 */
roundkey xrijndaelKeySched(const void* key, int keyBits = ERijndaelBits256, int blockBits = ERijndaelBits128);

/*
 * @brief 加密数组
 *
 * @param handle 密钥句柄
 * @param block 待加密数组，长度与句柄中的blockBits一致，直接覆盖数组
 */
void xrijndaelEncrypt(const roundkey& handle, const void* block);

/*
 * @brief 解译数组
 *
 * @param handle 密钥句柄
 * @param block 待解译数组，长度与句柄中的blockBits一致，直接覆盖数组
 */
void xrijndaelDecrypt(const roundkey& handle, const void* block);


#endif              /* __RIJNDAEL_H */
