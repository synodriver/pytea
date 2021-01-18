/******************************************************************************
 * File: TEA_Encrypt.c
 * Author: Bean
 * Email: notrynohigh@outlook.com
 * Every one can use this file free !
 ******************************************************************************/
/** Include -----------------------------------------------------------------*/
#include "stdio.h"
#include "tea.h"

/** defined -----------------------------------------------------------------*/
#define TEA_DELTA                  0x9e3779b9
#define TEA_KEY_LEN                (16)

/** global variable --------------------------------------------------------*/
static TEA_U8 gTEA_EncryptTimes = 16;
static TEA_U8 gTEA_KeyBuf[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};



/** static functions -------------------------------------------------------*/
TEA_ErrorCode_t TEA_EncryptGroup(TEA_U32 *text, TEA_U32 *key) // 传入8字节数据 16字节key todo 这个函数有问题
{
    TEA_U32 sum = 0, v0 = text[0], v1 = text[1]; // 2个4字节数据 要进行加密的数据 todo v1 v2字节序有问题
    TEA_U32 k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3]; // 4个key,每个4字节 todo key 字节序有问题
    TEA_U8 i = 0;
    printf("v0 %u v1 %u\n",v0,v1); //todo del

    if(text == TEA_NULL || key == TEA_NULL)
    {
        return TEA_ERROR;
    }

    for(i = 0;i < gTEA_EncryptTimes;i++)
    {
        sum += TEA_DELTA;
        v0 += (v1 << 4) + k0 ^ v1 + sum ^ (v1 >> 5) + k1;
		v1 += (v0 << 4) + k2 ^ v0 + sum ^ (v0 >> 5) + k3;
    }
    text[0] = v0;
    text[1] = v1;
    return TEA_SUCCESS;
}

TEA_ErrorCode_t TEA_DecryptGroup(TEA_U32 *text, TEA_U32 *key) // 解密一组  8字节数据 16字节key
{
    TEA_U32 sum = TEA_DELTA * gTEA_EncryptTimes, v0 = text[0], v1 = text[1];
    TEA_U32 k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];

    TEA_U8 i = 0;

    if(text == TEA_NULL || key == TEA_NULL)
    {
        return TEA_ERROR;
    }

    for(i = 0;i < gTEA_EncryptTimes;i++)
    {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= TEA_DELTA;
    }
    text[0] = v0;
    text[1] = v1;
    return TEA_SUCCESS;
}




/** public functions -------------------------------------------------------*/
TEA_ErrorCode_t TEA_Config128bitsKey(TEA_U8 *key) // 16 字节key
{
    TEA_U8 i = 0;
    if(key == TEA_NULL)
    {
        return TEA_ERROR;
    }
    for(i = 0;i < TEA_KEY_LEN;i++)
    {
        gTEA_KeyBuf[i] = key[i];
    }
    return TEA_SUCCESS;
}


TEA_ErrorCode_t TEA_ConfigEncryptTimes(TEA_U8 t)
{
    gTEA_EncryptTimes = (t < 16) ? 16 : t;
    return TEA_SUCCESS;
}



TEA_ErrorCode_t TEA_Encrypt(TEA_U8 *text, TEA_U32 size)
{
    TEA_U32 number = size >> 3;  // size是字节数  8个字节一组进行加密 需要number组  进来的应该已经补充成了8n个字节
    TEA_U8  i = 0;

    if(text == NULL || size < 8)
    {
        TEA_DEBUG("at least eight bytes !\n\r");
        return TEA_ERROR;
    }
//    printf("%s len %u\n",text,size); // todo del
    TEA_U64 tr = 0;
    TEA_U64 to = 0;
    TEA_U64 o = 0;
    printf("outside v0 %u v1 %u\n",((TEA_U32 *)text)[0],((TEA_U32 *)text)[1]); //todo del  前处理没有生效
    for(i = 0;i < number;i++)  // 8字节是一组 number组
    {
        o = ((TEA_U64*) text)[i] ^ tr; //  第一次xor  8字节与tr异或 todo 抄pytea.py line75
        //TEA_EncryptGroup(&(((TEA_U32 *)text)[i * 2]), (TEA_U32 *)gTEA_KeyBuf); // 八个字节加密了  key16字节
        TEA_EncryptGroup((TEA_U32 *)(&o), (TEA_U32 *)gTEA_KeyBuf);
        tr = o ^ to;
        to = o;
        ((TEA_U64*) text)[i] = tr;
    }
    return TEA_SUCCESS;
}


TEA_ErrorCode_t TEA_Decrypt(TEA_U8 *text, TEA_U32 size)
{
    TEA_U32 number = size >> 3;
    TEA_U8  i = 0;

    if(text == NULL || size < 8)
    {
        TEA_DEBUG("at least eight characters !\n\r");
        return TEA_ERROR;
    }

    TEA_DecryptGroup(&(((TEA_U32 *)text)[0]), (TEA_U32 *)gTEA_KeyBuf);
    TEA_U8 pos = text[0] & 0x07 + 2;

    for(i = 1;i < number;i++)
    {
        TEA_DecryptGroup(&(((TEA_U32 *)text)[i * 2]), (TEA_U32 *)gTEA_KeyBuf);
    }
    text += pos;
    return TEA_SUCCESS;
}
/******************************************************************************
* end !
******************************************************************************/







