# cython: language_level=3
cimport tea

cdef class TEA:
    """TEA加密的py绑定"""
    cdef public char*secret_key
    cdef public int encrypt_times

    def __init__(self, secret_key, int encrypt_times=16):
        self.secret_key = secret_key
        self.encrypt_times = encrypt_times
        cdef int flag = tea.TEA_Config128bitsKey(<tea.TEA_U8*>self.secret_key)
        if flag != tea.TEA_SUCCESS:
            raise Exception("sth wrong")
        tea.TEA_ConfigEncryptTimes(<tea.TEA_U8> self.encrypt_times)

    cpdef encrypt(self, text):
        cdef char*temp_data = text
        cdef int flag = tea.TEA_Encrypt(<tea.TEA_U8*> temp_data, <tea.TEA_U32> len(text))
        if flag == 0:
            raise ValueError("encrypt failed")
        elif flag == 2:
            raise MemoryError("out of memory")
        elif flag == 3:
            raise Exception("sth wrong")
        return <bytes> temp_data

    cpdef decrypt(self, text):
        cdef char*temp_data = text
        cdef int flag = tea.TEA_Decrypt(<tea.TEA_U8*> temp_data, <tea.TEA_U32> len(text))
        if flag == 0:
            raise ValueError("decrypt failed")
        elif flag == 2:
            raise MemoryError("out of memory")
        elif flag == 3:
            raise Exception("sth wrong")
        return <bytes> temp_data
