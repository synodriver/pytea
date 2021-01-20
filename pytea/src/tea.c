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
//    printf("inside TEA_EncryptGroup  v0 %u v1 %u\n",v0,v1); //todo del

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
//    printf("inside  TEA_EncryptGroup after jiami  v0 %u v1 %u\n",v0,v1); //todo del
    return TEA_SUCCESS;
}

TEA_ErrorCode_t TEA_DecryptGroup(TEA_U32* text, TEA_U32* key) // 解密一组  8字节数据 16字节key
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
    TEA_U32  i = 0;

    if(text == NULL || size < 8)
    {
        TEA_DEBUG("at least eight bytes !\n\r");
        return TEA_ERROR;
    }
//    printf("text len %u\n",size); // todo 4096个字节传进来了
    TEA_U64 tr = 0;
    TEA_U64 to = 0;
    TEA_U64 o = 0;
    TEA_U64 o_temp = 0;
//    printf("outside v0 %u v1 %u\n",((TEA_U32 *)text)[0],((TEA_U32 *)text)[1]); //todo del  前处理没有生效
    for(i = 0;i < number;i++)  // 8字节是一组 number组
    {
        o = ((TEA_U64*) text)[i] ^ tr; //  第一次xor  8字节与tr异或 todo 抄pytea.py line75
        //TEA_EncryptGroup(&(((TEA_U32 *)text)[i * 2]), (TEA_U32 *)gTEA_KeyBuf); // 八个字节加密了  key16字节
        o_temp = o;
        TEA_EncryptGroup((TEA_U32 *)(&o_temp), (TEA_U32 *)gTEA_KeyBuf); //!! 这里传指针出了问题 o自己不能改变
        tr = o_temp ^ to;
//        printf("outside o_temp = %u %u\n",((TEA_U32 *)(&o_temp))[0],((TEA_U32 *)(&o_temp))[1]); // todo del 看看tr的值  !! 这里传指针出了问题
//        printf("outside tr = %u %u\n",((TEA_U32 *)(&tr))[0],((TEA_U32 *)(&tr))[1]);
        to = o;
        ((TEA_U64*) text)[i] = tr;
    }
    return TEA_SUCCESS;
}


TEA_ErrorCode_t TEA_Decrypt(TEA_U8 *text, TEA_U32 size, TEA_U8* tag) // char* 字节数  一定是8的倍数 tag用来传递前面要跳过多少字节的填充数据 自行处理
{
    TEA_U32 number = size >> 3;  // 8字节是一组 分为number组
    TEA_U32  i = 0;

    if(text == NULL || size < 8)
    {
        TEA_DEBUG("at least eight characters !\n\r");
        return TEA_ERROR;
    }
    // text 先不要变
    TEA_U64 PrePlain = 0;
    TEA_U64 ret = 0; // 代表返回值
    TEA_U64 PreCrypt = 0;
    TEA_U64 x = 0; // 也是返回值
    TEA_U64 temp = 0; //来存储暂时的text
    TEA_U8 pos = 0;

    temp = ((TEA_U64*)text)[0];
    TEA_DecryptGroup((TEA_U32*)(&temp), (TEA_U32 *)gTEA_KeyBuf); // 变的是temp 无所谓了

    PrePlain = temp; // 第一次解密后的8个字节
    pos = (((TEA_U8*)(&PrePlain))[3] & 0x07) + 2; // 注意和py里面的字节序的差异 每4个字节就要反序
    ret = PrePlain;
    PreCrypt = ((TEA_U64*)text)[0];  // 前8个字节
    ((TEA_U64*)text)[0] = ret; //返回值注入了

    for(i = 1;i < number;i++) // 跳过了前8个字节
    {
        temp = (((TEA_U64*)text)[i]) ^ PrePlain;
        TEA_DecryptGroup((TEA_U32*)(&temp), (TEA_U32 *)gTEA_KeyBuf); // temp 自己就被改变了
        ret = temp ^ PreCrypt;
        PrePlain = ret ^ PreCrypt;
        PreCrypt = ((TEA_U64*)text)[i];
        ((TEA_U64*)text)[i] = ret;

    }
    *tag = pos+1; // text[pos+1,-7]
    return TEA_SUCCESS;
}
/******************************************************************************
* end !
******************************************************************************/







