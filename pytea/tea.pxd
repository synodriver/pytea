# cython: language_level=3
cdef extern from "src/tea.h":
    ctypedef unsigned char  TEA_U8
    ctypedef signed char    TEA_S8
    ctypedef unsigned short TEA_U16
    ctypedef signed short   TEA_S16
    ctypedef unsigned int   TEA_U32
    ctypedef signed int     TEA_S32
    ctypedef unsigned long long TEA_U64

    ctypedef enum TEA_ErrorCode_t:
        TEA_ERROR
        TEA_SUCCESS
        TEA_MEMORY_ERROR
        TEA_OTHERS

    cdef TEA_ErrorCode_t TEA_Config128bitsKey(TEA_U8 *key)
    cdef TEA_ErrorCode_t TEA_ConfigEncryptTimes(TEA_U8 t)

    cdef TEA_ErrorCode_t TEA_Encrypt(TEA_U8 *text, TEA_U32 size)
    cdef TEA_ErrorCode_t TEA_Decrypt(TEA_U8 *text, TEA_U32 size,TEA_U8* tag)


    cdef TEA_ErrorCode_t TEA_EncryptGroup(TEA_U32 *text, TEA_U32 *key)
    cdef TEA_ErrorCode_t TEA_DecryptGroup(TEA_U32 *text, TEA_U32 *key)