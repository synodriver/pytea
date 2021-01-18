# cython: language_level=3
import struct

from pytea cimport tea

cdef char*conv(char*data, int size):
    """
    转换字节序
    :param data: char数组
    :param size: 长度
    :return: 
    """
    cdef int i = 0
    cdef char temp
    for i in range(size // 2):
        temp = data[i]
        data[i] = data[size - i - 1]
        data[size - i - 1] = temp
    return data

cdef atoi(char* data):




cdef class TEA:
    """TEA加密的py绑定 secret_key实例化以后就确定了,再更改是没用的"""
    cdef char _secret_key[16]
    cdef int _encrypt_times

    def __init__(self, bytes secret_key, int encrypt_times=16):
        k = struct.unpack('>LLLL', secret_key[0:16])
        cdef int i
        for i in range(4):
            (<tea.TEA_U32*> self._secret_key)[i] = <tea.TEA_U32> (k[i])

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
        cdef tea.TEA_U32 k0 = (<tea.TEA_U32*> self._secret_key)[0]
        cdef tea.TEA_U32 k1 = (<tea.TEA_U32*> self._secret_key)[1]
        cdef tea.TEA_U32 k2 = (<tea.TEA_U32*> self._secret_key)[2]
        cdef tea.TEA_U32 k3 = (<tea.TEA_U32*> self._secret_key)[3]
        return struct.pack('>LLLL', k0, k1, k2, k3)

    @secret_key.setter
    def secret_key(self, bytes value):
        k = struct.unpack(b'>LLLL', value[0:16])  # 16字节value 4个ulong
        cdef int i
        for i in range(4):
            (<tea.TEA_U32*> self._secret_key)[i] = <tea.TEA_U32> (k[i])
        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Config128bitsKey(<tea.TEA_U8*> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("set key wrong")

    cpdef encrypt_group(self, bytes text):
        """
        加密一组 8个字节数据
        :param text: 8字节 bytes
        :return: 
        """
        cdef char* temp_data = text
        conv(temp_data, 8)  # 没4个字节切换一次顺序
        cdef tea.TEA_U32 v0 = (<tea.TEA_U32*> temp_data)[1]
        cdef tea.TEA_U32 v1 = (<tea.TEA_U32*> temp_data)[0]
        cdef tea.TEA_U32[2] real = {v0, v1}

        cdef int flag = tea.TEA_EncryptGroup(real, <tea.TEA_U32 *> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("sth wrong")
        v0 = real[0]
        v1 = real[1]
        r = struct.pack(b'>LL', v0, v1)
        return r  # 最后关头出问题

    cpdef decrypt_group(self, bytes text): # todo 进度
        """
        解密一组 8个字节数据
        :param text: 
        :return: 
        """
        cdef char* temp_data = text
        conv(temp_data, 8)  # 没4个字节切换一次顺序
        cdef tea.TEA_U32 v0 = (<tea.TEA_U32*> temp_data)[0]
        cdef tea.TEA_U32 v1 = (<tea.TEA_U32*> temp_data)[1]
        cdef tea.TEA_U32[2] real = {v0, v1}

        cdef int flag = tea.TEA_DecryptGroup(real, <tea.TEA_U32 *> self._secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("sth wrong")
        v0 = real[0]
        v1 = real[1]
        return struct.pack(b'>LL', v0, v1)

    cpdef encrypt(self, bytes text):
        """
        需要填充为8字节的整数倍数
        :param text: 
        :return: 
        """
        # cdef tea.TEA_U8 bytes_to_fill = 220 # 网里面填充220
        n = (8 - (len(text) + 2)) % 8 + 2  # 填充字符的个数 显然, n至少为2, 取2到9之间
        fill_n_or = (n - 2) | 0xF8  # 然后在填充字符前部插入1字节, 值为 ((n - 2)|0xF8) 以便标记填充字符的个数.
        text = bytes([fill_n_or]) + bytes([220]) * n + text + b'\x00' * 7  # 填充

        cdef char*temp_data = text # 传进去字节序又变了

        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Encrypt(<tea.TEA_U8*> temp_data, <tea.TEA_U32> len(text))
        if flag == tea.TEA_ERROR:
            raise ValueError("encrypt failed")
        elif flag == tea.TEA_MEMORY_ERROR:
            raise MemoryError("out of memory")
        elif flag == tea.TEA_OTHERS:
            raise Exception("sth wrong")
        return <bytes> temp_data

    cpdef decrypt(self, bytes text):
        """
        解密后,应该除去加密的时候填充的字节
        :param text: 
        :return: 
        """
        cdef int l = len(text)
        if l % 8 != 0 or l < 16:
            raise ValueError("decrypt failed, len%8！=0")

        cdef char*temp_data = text
        cdef tea.TEA_ErrorCode_t flag = tea.TEA_Decrypt(<tea.TEA_U8*> temp_data, <tea.TEA_U32> l)
        if flag == tea.TEA_ERROR:
            raise ValueError("decrypt failed")
        elif flag == tea.TEA_MEMORY_ERROR:
            raise MemoryError("out of memory")
        elif flag == tea.TEA_OTHERS:
            raise Exception("sth wrong")
        data = <bytes> temp_data
        if data[-7:] != b"\x00" * 7:
            raise ValueError("decrypt failed: illegal bytes ends without 0000000")
