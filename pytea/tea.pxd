# cython: language_level=3
from libc.stdint cimport uint8_t, uint32_t
cdef extern from "tea.h" nogil:
    ctypedef enum TEA_ErrorCode:
        TEA_ERROR
        TEA_SUCCESS
        TEA_MEMORY_ERROR
        TEA_OTHERS

    ctypedef struct TEAObject:
        uint8_t encrypt_times
        uint8_t key[16]

    cdef TEAObject * TEAObject_New()

    cdef TEA_ErrorCode TEAObject_Init(TEAObject *self, uint8_t *key, uint8_t times)

    cdef void TEAObject_Del(TEAObject** self)

    cdef TEA_ErrorCode TEAObject_SetKey(TEAObject *self, uint8_t *key)

    cdef TEA_ErrorCode TEAObject_SetEncryptTimes(TEAObject *self, uint8_t t)

    cdef TEA_ErrorCode TEAObject_Encrypt(TEAObject *self, uint8_t *text, uint32_t size)

    cdef TEA_ErrorCode TEAObject_Decrypt(TEAObject *self, uint8_t *text, uint32_t size, uint8_t *tag)

    cdef TEA_ErrorCode TEAObject_EncryptGroup(TEAObject *self, uint32_t *text, uint32_t *key)

    cdef TEA_ErrorCode TEAObject_DecryptGroup(TEAObject *self, uint32_t *text, uint32_t *key)

    cdef void TEA_SwapEndian(uint8_t *data, uint32_t size)

    cdef bint TEA_CheckPy()