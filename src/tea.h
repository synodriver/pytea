//
// Created by jhc on 2021/11/22.
//

#ifndef PYTEA_TEA_H
#define PYTEA_TEA_H

/******************************************************************************
 * File: TEA_Encrypt.h
 * Author: Bean
 * Email: notrynohigh@outlook.com
 * Every one can use this file free !
 ******************************************************************************/

/******************************************************************************
 *  basic data type
 ******************************************************************************/
#include<stdio.h>
#include<string.h>
#include<stdint.h>

/******************************************************************************
 *  define
 ******************************************************************************/
#define TEA_DEBUG_ENABLE      1

#if TEA_DEBUG_ENABLE
#define TEA_DEBUG(...)    printf(__VA_ARGS__)
#else
#define TEA_DEBUG(...)
#endif

#ifdef PYTHON
#include "Python.h"
#define mallocfunc PyMem_Malloc
#define freefunc PyMem_Free
#else
#include<stdlib.h>
#define mallocfunc malloc
#define freefunc free
#endif

/******************************************************************************
 *  typedef enum
 ******************************************************************************/
typedef enum
{
    TEA_ERROR,
    TEA_SUCCESS,
    TEA_MEMORY_ERROR,
    TEA_OTHERS
} TEA_ErrorCode;


typedef struct
{
    uint8_t encrypt_times;
    uint8_t key[16];
} TEAObject;

/******************************************************************************
 * public functions
 ******************************************************************************/
TEAObject* TEAObject_New();

TEA_ErrorCode TEAObject_Init(TEAObject *self, uint8_t *key, uint8_t times);

void TEAObject_Del(TEAObject** self);

TEA_ErrorCode TEAObject_SetKey(TEAObject *self,uint8_t *key);

TEA_ErrorCode TEAObject_SetEncryptTimes(TEAObject *self,uint8_t t);

TEA_ErrorCode TEAObject_Encrypt(TEAObject *self,uint8_t *text, uint32_t size);

TEA_ErrorCode TEAObject_Decrypt(TEAObject *self,uint8_t *text, uint32_t size, uint8_t *tag);

TEA_ErrorCode TEAObject_EncryptGroup(TEAObject *self,uint32_t *text, uint32_t *key);

TEA_ErrorCode TEAObject_DecryptGroup(TEAObject *self,uint32_t *text, uint32_t *key);

void TEA_SwapEndian(uint8_t *data, uint32_t size);
/******************************************************************************
 *  Reserved !
 ******************************************************************************/
#endif //PYTEA_TEA_H
