# cython: language_level=3
cimport cython
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from libc.string cimport memcpy
from libc.stdint cimport uint8_t, uint32_t

from pytea cimport tea

cdef class TEA:
    """TEA binding for python"""
    cdef tea.TEAObject * _tea
    cdef const uint8_t[:] _key
    cdef uint8_t _encrypt_times

    def __cinit__(self, const uint8_t[:] secret_key, uint8_t encrypt_times=16):  # bytes会被改变
        # k = struct.unpack('>LLLL', secret_key[0:16])
        self._key = secret_key
        self._encrypt_times = encrypt_times
        self._tea = tea.TEAObject_New()
        if self._tea is NULL:
            raise MemoryError()

        cdef uint8_t *temp_data = <uint8_t *> PyMem_Malloc(16 * sizeof(uint8_t))
        if temp_data is NULL:
            raise MemoryError()
        memcpy(temp_data, &secret_key[0], 16)
        tea.TEA_SwapEndian(temp_data, 16)
        cdef tea.TEA_ErrorCode flag = tea.TEAObject_Init(self._tea, temp_data, encrypt_times)
        PyMem_Free(temp_data)

        if flag != tea.TEA_SUCCESS:
            raise ValueError("init tea object error")

    def __dealloc__(self):
        if self._tea is not NULL:
            tea.TEAObject_Del(&self._tea)

    @property
    def encrypt_times(self):
        return self._encrypt_times

    @encrypt_times.setter
    def encrypt_times(self, int value):
        tea.TEAObject_SetEncryptTimes(self._tea, self._encrypt_times)
        self._encrypt_times = value

    @property
    def key(self):
        return bytes(self._key)

    @key.setter
    def key(self, const uint8_t[:] value):
        cdef uint8_t *temp_data = <uint8_t *> PyMem_Malloc(16 * sizeof(uint8_t))
        if temp_data is NULL:
            raise MemoryError()
        memcpy(temp_data, &value[0], 16)
        tea.TEA_SwapEndian(temp_data, 16)
        cdef tea.TEA_ErrorCode flag = tea.TEAObject_SetKey(self._tea, temp_data)
        if flag != tea.TEA_SUCCESS:
            raise ValueError("set key error")
        PyMem_Free(temp_data)
        self._key = value

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cpdef bytes encrypt_group(self, const uint8_t[:] text):
        """
        encrypt_group(self, bytes text) -> bytes
        
        加密一组 8个字节数据
        :param text: 8字节 bytes
        :return: 
        """
        cdef uint8_t *temp_data = <uint8_t *> PyMem_Malloc(8 * sizeof(uint8_t))
        if temp_data is NULL:
            raise MemoryError()
        memcpy(temp_data, &text[0], 8)
        tea.TEA_SwapEndian(temp_data, 8)  # 没4个字节切换一次顺序

        cdef tea.TEA_ErrorCode flag = tea.TEAObject_EncryptGroup(self._tea, <uint32_t *> temp_data,
                                                                 <uint32_t *> self._tea.key)
        if flag != tea.TEA_SUCCESS:
            raise ValueError("encrypt_group error")
        tea.TEA_SwapEndian(temp_data, 8)
        try:
            return <bytes> temp_data[0:8]  # 最后关头出问题
        finally:
            PyMem_Free(temp_data)

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cpdef bytes decrypt_group(self, const uint8_t[:] text):
        """
        decrypt_group(self, bytes text) -> bytes
        
        解密一组 8个字节数据
        :param text: 
        :return: 
        """
        cdef uint8_t *temp_data = <uint8_t *> PyMem_Malloc(8 * sizeof(uint8_t))
        if temp_data is NULL:
            raise MemoryError()
        memcpy(temp_data, &text[0], 8)
        tea.TEA_SwapEndian(temp_data, 8)  # 没4个字节切换一次顺序

        cdef tea.TEA_ErrorCode flag = tea.TEAObject_DecryptGroup(self._tea, <uint32_t *> temp_data,
                                                                 <uint32_t *> self._tea.key)
        if flag != tea.TEA_SUCCESS:
            raise ValueError("decrypt_group error")
        tea.TEA_SwapEndian(temp_data, 8)
        try:
            return <bytes> temp_data[0:8]
        finally:
            PyMem_Free(temp_data)

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cpdef bytes encrypt(self, const uint8_t[:] text):
        """
        encrypt(self, bytes text) -> bytes
        
        需要填充为8字节的整数倍数
        :param text: 要加密的数据
        :return: 
        """
        n = (8 - (text.shape[0] + 2)) % 8 + 2  # 填充字符的个数 显然, n至少为2, 取2到9之间 py division
        # n = (8 - (len(text) + 2)) % 8  # this allows cdivision in cython
        # n = n + 2 if n >= 0 else n + 10  # simulate py division

        fill_n_or = (n - 2) | 0xF8  # 然后在填充字符前部插入1字节, 值为 ((n - 2)|0xF8) 以便标记填充字符的个数.
        text = bytes([fill_n_or]) + bytes([220]) * n + bytes(text) + b'\x00' * 7  # 填充 type: bytes

        cdef Py_ssize_t l = len(text)
        cdef uint8_t *temp_data = <uint8_t *> PyMem_Malloc(l * sizeof(uint8_t))
        if temp_data is NULL:
            raise MemoryError()
        memcpy(temp_data, &text[0], l)
        tea.TEA_SwapEndian(temp_data, <uint32_t> l)  # 转换字节序 事实证明这一步走对了

        cdef tea.TEA_ErrorCode flag = tea.TEAObject_Encrypt(self._tea, temp_data, <uint32_t> len(text))
        if flag == tea.TEA_ERROR:
            raise ValueError("encrypt error")
        elif flag == tea.TEA_MEMORY_ERROR:
            raise MemoryError()
        elif flag == tea.TEA_OTHERS:
            raise ValueError("encrypt other error")
        tea.TEA_SwapEndian(temp_data, <uint32_t> l)
        try:
            return <bytes> temp_data[0:l]
        finally:
            PyMem_Free(temp_data)

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cpdef bytes decrypt(self, const uint8_t[:] text):
        """
        decrypt(self, bytes text) -> bytes
        
        传入填充了的数据 解密后,应该除去加密的时候填充的字节
        :param text: 要解密的数据
        :return: 
        """
        cdef Py_ssize_t l = text.shape[0]
        if l % 8 != 0 or l < 16:
            raise ValueError("decrypt failed, len%8!=0")

        cdef uint8_t tag = 0

        cdef uint8_t * temp_data = <uint8_t *> PyMem_Malloc(l * sizeof(uint8_t))
        if temp_data is NULL:
            raise MemoryError()
        memcpy(temp_data, &text[0], l)
        tea.TEA_SwapEndian(temp_data, <uint32_t> l)

        cdef tea.TEA_ErrorCode flag = tea.TEAObject_Decrypt(self._tea, temp_data, <uint32_t> l, &tag)
        if flag == tea.TEA_ERROR:
            raise ValueError("decrypt error")
        elif flag == tea.TEA_MEMORY_ERROR:
            raise MemoryError()
        elif flag == tea.TEA_OTHERS:
            raise ValueError("decrypt other error")

        tea.TEA_SwapEndian(temp_data, <uint32_t> l)
        # print(f"len {l}")
        data = <bytes> temp_data[0:l]
        # print(data)
        if data[l - 7:] != b"\x00" * 7:
            raise ValueError("decrypt failed: illegal bytes ends without 0000000")
        try:
            return data[tag:l - 7]
        finally:
            PyMem_Free(temp_data)

cpdef bint check_pymalloc():
    """
    check if PyMem_Malloc is used in libtea
    :return: bool
    """
    return tea.TEA_CheckPy()