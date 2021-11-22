//
// Created by synodriver on 2021/11/22.
//
#include "tea.h"

/** defined -----------------------------------------------------------------*/
#define TEA_DELTA                  0x9e3779b9
#define TEA_KEY_LEN                (16)

/** global variable --------------------------------------------------------*/
//static uint8_t TEA_EncryptTimes = 16;
//static uint8_t gTEA_KeyBuf[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};


/** static functions -------------------------------------------------------*/
TEAObject *TEAObject_New()
{
    TEAObject *self = (TEAObject *) mallocfunc(sizeof(TEAObject));
    if (self == NULL)
    {
        return NULL;
    }
    return self;
}

TEA_ErrorCode TEAObject_Init(TEAObject *self, uint8_t *key, uint8_t times)
{
    TEA_ErrorCode code = TEAObject_SetKey(self, key);
    if (code != TEA_SUCCESS)
    {
        return code;
    }
    return TEAObject_SetEncryptTimes(self, times);
}

void TEAObject_Del(TEAObject **self)
{
    if (*self != NULL)
    {
        freefunc(*self);
        *self = NULL;
    }
}

TEA_ErrorCode TEAObject_SetKey(TEAObject *self, uint8_t *key) // 16 字节key
{
    if (key == NULL)
    {
        return TEA_ERROR;
    }
    memcpy(self->key, key, 16);
    return TEA_SUCCESS;
}


TEA_ErrorCode TEAObject_SetEncryptTimes(TEAObject *self, uint8_t t)
{
    self->encrypt_times = (t < 16) ? 16 : t;
    return TEA_SUCCESS;
}


TEA_ErrorCode TEAObject_EncryptGroup(TEAObject *self, uint32_t *text, uint32_t *key) // 传入8字节数据 16字节key todo 这个函数有问题
{
    uint32_t sum = 0, v0 = text[0], v1 = text[1]; // 2个4字节数据 要进行加密的数据 todo v1 v2字节序有问题
    uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3]; // 4个key,每个4字节 todo key 字节序有问题
    uint8_t i;
//    printf("inside TEAObject_EncryptGroup  v0 %u v1 %u\n",v0,v1); //todo del

    if (text == NULL || key == NULL)
    {
        return TEA_ERROR;
    }

    for (i = 0; i < self->encrypt_times; i++)
    {
        sum += TEA_DELTA;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }
    text[0] = v0;
    text[1] = v1;
//    printf("inside  TEA_EncryptGroup after jiami  v0 %u v1 %u\n",v0,v1); //todo del
    return TEA_SUCCESS;
}

TEA_ErrorCode TEAObject_DecryptGroup(TEAObject *self, uint32_t *text, uint32_t *key) // 解密一组  8字节数据 16字节key
{
    uint32_t sum = TEA_DELTA * self->encrypt_times, v0 = text[0], v1 = text[1];
    uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];

    uint8_t i;

    if (text == NULL || key == NULL)
    {
        return TEA_ERROR;
    }

    for (i = 0; i < self->encrypt_times; i++)
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


TEA_ErrorCode TEAObject_Encrypt(TEAObject *self, uint8_t *text, uint32_t size)
{
    uint32_t number = size >> 3;  // size是字节数  8个字节一组进行加密 需要number组  进来的应该已经补充成了8n个字节
    uint32_t i;

    if (text == NULL || size < 8)
    {
        TEA_DEBUG("at least eight bytes !\n\r");
        return TEA_ERROR;
    }
//    printf("text len %u\n",size); // todo 4096个字节传进来了
    uint64_t tr = 0;
    uint64_t to = 0;
    uint64_t o;
    uint64_t o_temp = 0;
//    printf("outside v0 %u v1 %u\n",((uint32_t *)text)[0],((uint32_t *)text)[1]); //todo del  前处理没有生效
    for (i = 0; i < number; i++)  // 8字节是一组 number组
    {
        o = ((uint64_t *) text)[i] ^ tr; //  第一次xor  8字节与tr异或 todo 抄pytea.py line75
        //TEA_EncryptGroup(&(((uint32_t *)text)[i * 2]), (uint32_t *)self->key); // 八个字节加密了  key16字节
        o_temp = o;
        TEAObject_EncryptGroup(self, (uint32_t * )(&o_temp), (uint32_t *) self->key); //!! 这里传指针出了问题 o自己不能改变
        tr = o_temp ^ to;
//        printf("outside o_temp = %u %u\n",((uint32_t *)(&o_temp))[0],((uint32_t *)(&o_temp))[1]); // todo del 看看tr的值  !! 这里传指针出了问题
//        printf("outside tr = %u %u\n",((uint32_t *)(&tr))[0],((uint32_t *)(&tr))[1]);
        to = o;
        ((uint64_t *) text)[i] = tr;
    }
    return TEA_SUCCESS;
}


TEA_ErrorCode TEAObject_Decrypt(TEAObject *self, uint8_t *text, uint32_t size,
                                uint8_t *tag) // char* 字节数  一定是8的倍数 tag用来传递前面要跳过多少字节的填充数据 自行处理
{
    uint32_t number = size >> 3;  // 8字节是一组 分为number组
    uint32_t i = 0;

    if (text == NULL || size < 8)
    {
        TEA_DEBUG("at least eight characters !\n\r");
        return TEA_ERROR;
    }
    // text 先不要变
    uint64_t PrePlain = 0;
    uint64_t ret = 0; // 代表返回值
    uint64_t PreCrypt = 0;
    uint64_t temp = 0; //来存储暂时的text
    uint8_t pos = 0;

    temp = ((uint64_t *) text)[0];
    TEAObject_DecryptGroup(self, (uint32_t * )(&temp), (uint32_t *) self->key); // 变的是temp 无所谓了

    PrePlain = temp; // 第一次解密后的8个字节
    pos = (((uint8_t * )(&PrePlain))[3] & 0x07) + 2; // 注意和py里面的字节序的差异 每4个字节就要反序
    ret = PrePlain;
    PreCrypt = ((uint64_t *) text)[0];  // 前8个字节
    ((uint64_t *) text)[0] = ret; //返回值注入了

    for (i = 1; i < number; i++) // 跳过了前8个字节
    {
        temp = (((uint64_t *) text)[i]) ^ PrePlain;
        TEAObject_DecryptGroup(self, (uint32_t * )(&temp), (uint32_t *) self->key); // temp 自己就被改变了
        ret = temp ^ PreCrypt;
        PrePlain = ret ^ PreCrypt;
        PreCrypt = ((uint64_t *) text)[i];
        ((uint64_t *) text)[i] = ret;
    }
    *tag = pos + 1; // text[pos+1,-7]
    return TEA_SUCCESS;
}
/******************************************************************************
* end !
******************************************************************************/