# cython: language_level=3
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy
from pytea cimport tea

cdef tea.TEA_U8*conv(tea.TEA_U8*data, int size):
    """
    倒叙
    :param data: char数组
    :param size: 长度
    :return: 
    """
    cdef int i = 0
    cdef tea.TEA_U8 temp
    for i in range(size // 2):
        temp = data[i]
        data[i] = data[size - i - 1]
        data[size - i - 1] = temp
    return data

cdef void ntohs(tea.TEA_U8*data, int size):
    cdef int i = 0
    for i in range(0, size, 4):
        conv(data + i, 4)

cdef class TEA:
    """TEA加密的py绑定"""
    cdef char _secret_key[16]
    cdef int _encrypt_times

    def __init__(self, bytes secret_key, int encrypt_times=16):  # bytes会被改变
        # k = struct.unpack('>LLLL', secret_key[0:16])
        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> malloc(16 * sizeof(tea.TEA_U8))
        if not temp_data:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> secret_key, 16)
        # cdef tea.TEA_U8*temp_data = secret_key
        ntohs(temp_data, 16)
        cdef tea.TEA_U8 i
        for i in range(4):
            (<tea.TEA_U32*> self._secret_key)[i] = (<tea.TEA_U32*> temp_data)[i]
        free(temp_data)
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
        ntohs(<tea.TEA_U8*> key, 16)
        return <bytes> (<tea.TEA_U8*> key)[0:16]

    @secret_key.setter
    def secret_key(self, bytes value):
        cdef tea.TEA_U8* temp_data = <tea.TEA_U8*> malloc(16 * sizeof(tea.TEA_U8))
        if not temp_data:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> value, 16)
        ntohs(temp_data, 16)

        cdef tea.TEA_U8 i
        for i in range(4):
            (<tea.TEA_U32*> self._secret_key)[i] = (<tea.TEA_U32*> temp_data)[i]
        free(temp_data)
        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Config128bitsKey(<tea.TEA_U8*> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("set key wrong")

    cpdef bytes encrypt_group(self, bytes text):
        """
        加密一组 8个字节数据
        :param text: 8字节 bytes
        :return: 
        """
        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> malloc(8 * sizeof(tea.TEA_U8))
        if not temp_data:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> text, 8)
        ntohs(temp_data, 8)  # 没4个字节切换一次顺序

        cdef int flag = tea.TEA_EncryptGroup(<tea.TEA_U32 *> temp_data, <tea.TEA_U32 *> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("sth wrong")
        ntohs(temp_data, 8)
        return <bytes> temp_data[0:8]  # 最后关头出问题

    cpdef bytes decrypt_group(self, bytes text):
        """
        解密一组 8个字节数据
        :param text: 
        :return: 
        """
        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> malloc(8 * sizeof(tea.TEA_U8))
        if not temp_data:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> text, 8)
        ntohs(temp_data, 8)  # 没4个字节切换一次顺序

        cdef int flag = tea.TEA_DecryptGroup(<tea.TEA_U32 *> temp_data, <tea.TEA_U32 *> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("sth wrong")
        ntohs(temp_data, 8)
        return <bytes> temp_data[0:8]

    cpdef encrypt(self, bytes text):
        """
        需要填充为8字节的整数倍数
        :param text: 
        :return: 
        """
        n = (8 - (len(text) + 2)) % 8 + 2  # 填充字符的个数 显然, n至少为2, 取2到9之间
        fill_n_or = (n - 2) | 0xF8  # 然后在填充字符前部插入1字节, 值为 ((n - 2)|0xF8) 以便标记填充字符的个数.
        text = bytes([fill_n_or]) + bytes([220]) * n + text + b'\x00' * 7  # 填充

        cdef int l = len(text)
        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> malloc(l * sizeof(tea.TEA_U8))
        if not temp_data:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> text, l)
        ntohs(temp_data, l)  # 转换字节序 事实证明这一步走对了

        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Encrypt(<tea.TEA_U8*> temp_data, <tea.TEA_U32> len(text))
        if flag == tea.TEA_ERROR:
            raise ValueError("encrypt failed")
        elif flag == tea.TEA_MEMORY_ERROR:
            raise MemoryError("out of memory")
        elif flag == tea.TEA_OTHERS:
            raise Exception("sth wrong")
        ntohs(temp_data, len(text))
        return <bytes> temp_data[0:len(text)]

    cpdef decrypt(self, bytes text):
        """
        传入填充了的数据 解密后,应该除去加密的时候填充的字节
        :param text: 
        :return: 
        """
        cdef int l = len(text)
        if l % 8 != 0 or l < 16:
            raise ValueError("decrypt failed, len%8!=0")

        cdef tea.TEA_U8 tag = 0

        cdef tea.TEA_U8*temp_data = <tea.TEA_U8*> malloc(l * sizeof(tea.TEA_U8))
        if not temp_data:
            raise MemoryError("no enough memory")
        memcpy(temp_data, <tea.TEA_U8*> text, l)
        ntohs(temp_data, l)

        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Decrypt(<tea.TEA_U8*> temp_data, <tea.TEA_U32> l, &tag)
        if flag == tea.TEA_ERROR:
            raise ValueError("decrypt failed")
        elif flag == tea.TEA_MEMORY_ERROR:
            raise MemoryError("out of memory")
        elif flag == tea.TEA_OTHERS:
            raise Exception("sth wrong")

        ntohs(temp_data, l)
        # print(f"len {l}")
        data = <bytes> temp_data[0:l]
        # print(data)
        if data[-7:] != b"\x00" * 7:
            raise ValueError("decrypt failed: illegal bytes ends without 0000000")
        return data[tag:-7]
