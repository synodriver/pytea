# cython: language_level=3
cimport cython
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from libc.string cimport memcpy

from pytea cimport tea

cdef tea.TEA_U8*conv(tea.TEA_U8*data, int size):
    """
    倒叙
    :param data: char数组
    :param size: 长度
    :return: 
    """
    cdef Py_ssize_t i = 0
    cdef tea.TEA_U8 temp
    for i in range(size // 2):
        temp = data[i]
        data[i] = data[size - i - 1]
        data[size - i - 1] = temp
    return data

cdef void swap_endian(tea.TEA_U8*data, Py_ssize_t size):
    cdef Py_ssize_t i = 0
    for i in range(0, size, 4):
        conv(data + i, 4)

cdef class TEA:
    """TEA加密的py绑定"""
    cdef char _secret_key[16]
    cdef int _encrypt_times

    def __cinit__(self, bytes secret_key, int encrypt_times=16):  # bytes会被改变
        # k = struct.unpack('>LLLL', secret_key[0:16])
        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> PyMem_Malloc(16 * sizeof(tea.TEA_U8))
        if temp_data is NULL:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> secret_key, 16)
        # cdef tea.TEA_U8*temp_data = secret_key
        swap_endian(temp_data, 16)
        cdef tea.TEA_U8 i
        for i in range(4):
            (<tea.TEA_U32*> self._secret_key)[i] = (<tea.TEA_U32*> temp_data)[i]
        PyMem_Free(temp_data)
        self._encrypt_times = encrypt_times
        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Config128bitsKey(<tea.TEA_U8*> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("set key wrong")
        tea.TEA_ConfigEncryptTimes(<tea.TEA_U8> self._encrypt_times)

    @property
    def encrypt_times(self):
        return self._encrypt_times

    @encrypt_times.setter
    def encrypt_times(self, int value):
        self._encrypt_times = value
        tea.TEA_ConfigEncryptTimes(<tea.TEA_U8> self._encrypt_times)

    @property
    def secret_key(self):
        cdef tea.TEA_U32 key[4]
        cdef tea.TEA_U8 i = 0
        for i in range(4):
            key[i] = (<tea.TEA_U32*> self._secret_key)[i]
        swap_endian(<tea.TEA_U8*> key, 16)
        return <bytes> (<tea.TEA_U8*> key)[0:16]

    @secret_key.setter
    def secret_key(self, bytes value):
        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> PyMem_Malloc(16 * sizeof(tea.TEA_U8))
        if temp_data is NULL:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> value, 16)
        swap_endian(temp_data, 16)

        cdef tea.TEA_U8 i
        for i in range(4):
            (<tea.TEA_U32*> self._secret_key)[i] = (<tea.TEA_U32*> temp_data)[i]
        PyMem_Free(temp_data)
        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Config128bitsKey(<tea.TEA_U8*> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise ValueError("set key wrong")

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cpdef bytes encrypt_group(self, bytes text):
        """
        加密一组 8个字节数据
        :param text: 8字节 bytes
        :return: 
        """
        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> PyMem_Malloc(8 * sizeof(tea.TEA_U8))
        if temp_data is NULL:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> text, 8)
        swap_endian(temp_data, 8)  # 没4个字节切换一次顺序

        cdef int flag = tea.TEA_EncryptGroup(<tea.TEA_U32 *> temp_data, <tea.TEA_U32 *> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("sth wrong")
        swap_endian(temp_data, 8)
        try:
            return <bytes> temp_data[0:8]  # 最后关头出问题
        finally:
            PyMem_Free(temp_data)

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cpdef bytes decrypt_group(self, bytes text):
        """
        解密一组 8个字节数据
        :param text: 
        :return: 
        """
        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> PyMem_Malloc(8 * sizeof(tea.TEA_U8))
        if temp_data is NULL:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> text, 8)
        swap_endian(temp_data, 8)  # 没4个字节切换一次顺序

        cdef int flag = tea.TEA_DecryptGroup(<tea.TEA_U32 *> temp_data, <tea.TEA_U32 *> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("sth wrong")
        swap_endian(temp_data, 8)
        try:
            return <bytes> temp_data[0:8]
        finally:
            PyMem_Free(temp_data)

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cpdef bytes encrypt(self, bytes text):
        """
        需要填充为8字节的整数倍数
        :param text: 要加密的数据
        :return: 
        """
        n = (8 - (len(text) + 2)) % 8 + 2  # 填充字符的个数 显然, n至少为2, 取2到9之间
        fill_n_or = (n - 2) | 0xF8  # 然后在填充字符前部插入1字节, 值为 ((n - 2)|0xF8) 以便标记填充字符的个数.
        text = bytes([fill_n_or]) + bytes([220]) * n + text + b'\x00' * 7  # 填充

        cdef Py_ssize_t l = len(text)
        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> PyMem_Malloc(l * sizeof(tea.TEA_U8))
        if temp_data is NULL:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> text, l)
        swap_endian(temp_data, l)  # 转换字节序 事实证明这一步走对了

        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Encrypt(<tea.TEA_U8*> temp_data, <tea.TEA_U32> len(text))
        if flag == tea.TEA_ERROR:
            raise ValueError("encrypt failed")
        elif flag == tea.TEA_MEMORY_ERROR:
            raise MemoryError("out of memory")
        elif flag == tea.TEA_OTHERS:
            raise ValueError("sth wrong")
        swap_endian(temp_data, l)
        try:
            return <bytes> temp_data[0:l]
        finally:
            PyMem_Free(temp_data)

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cpdef bytes decrypt(self, bytes text):
        """
        传入填充了的数据 解密后,应该除去加密的时候填充的字节
        :param text: 要解密的数据
        :return: 
        """
        cdef Py_ssize_t l = len(text)
        if l % 8 != 0 or l < 16:
            raise ValueError("decrypt failed, len%8!=0")

        cdef tea.TEA_U8 tag = 0

        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> PyMem_Malloc(l * sizeof(tea.TEA_U8))
        if temp_data is NULL:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> text, l)
        swap_endian(temp_data, l)

        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Decrypt(<tea.TEA_U8*> temp_data, <tea.TEA_U32> l, &tag)
        if flag == tea.TEA_ERROR:
            raise ValueError("decrypt failed")
        elif flag == tea.TEA_MEMORY_ERROR:
            raise MemoryError("out of memory")
        elif flag == tea.TEA_OTHERS:
            raise ValueError("sth wrong")

        swap_endian(temp_data, l)
        # print(f"len {l}")
        data = <bytes> temp_data[0:l]
        # print(data)
        if data[l-7:] != b"\x00" * 7:
            raise ValueError("decrypt failed: illegal bytes ends without 0000000")
        try:
            return data[tag:l-7]
        finally:
            PyMem_Free(temp_data)
