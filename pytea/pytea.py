# -*- coding: utf-8 -*-
import struct


def xor(a, b):
    op = 0xffffffff
    a1, a2 = struct.unpack(b'>LL', a[0:8])
    b1, b2 = struct.unpack(b'>LL', b[0:8])
    return struct.pack(b'>LL', (a1 ^ b1) & op, (a2 ^ b2) & op)


def tea_code(v, k) -> bytes:  # 传入8字节数据 16字节key
    n = 16
    op = 0xFFFFFFFF
    delta = 0x9E3779B9
    k = struct.unpack(b'>LLLL', k[0:16])
    v0, v1 = struct.unpack(b'>LL', v[0:8])
    sum_ = 0
    for i in range(n):
        sum_ += delta
        v0 += (op & (v1 << 4)) + k[0] ^ v1 + sum_ ^ (op & (v1 >> 5)) + k[1]
        v0 &= op
        v1 += (op & (v0 << 4)) + k[2] ^ v0 + sum_ ^ (op & (v0 >> 5)) + k[3]
        v1 &= op
    r = struct.pack(b'>LL', v0, v1)
    return r


def tea_decipher(v: bytes, k: bytes) -> bytes:
    n = 16
    op = 0xFFFFFFFF
    v0, v1 = struct.unpack('>LL', v[0:8])
    k0, k1, k2, k3 = struct.unpack(b'>LLLL', k[0:16])
    delta = 0x9E3779B9
    sum_ = (delta << 4) & op  # 左移4位 就是x16
    for i in range(n):
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum_) ^ ((v0 >> 5) + k3)
        v1 &= op
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum_) ^ ((v1 >> 5) + k1)
        v0 &= op
        sum_ -= delta
        sum_ &= op
    return struct.pack(b'>LL', v0, v1)


class TEA:
    """
    QQ TEA 加解密, 64比特明码, 128比特密钥
    这是一个确认线程安全的独立加密模块，使用时必须要有一个全局变量secret_key，要求大于等于16位
    """

    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key

    def encrypt(self, text: bytes):
        END_CHAR = b'\x00'
        FILL_N_OR = 0xF8
        vl = len(text)
        filln = (8 - (vl + 2)) % 8 + 2
        fills = b''
        for i in range(filln):
            fills = fills + bytes([220])
        text = (bytes([(filln - 2) | FILL_N_OR])
                + fills
                + text
                + END_CHAR * 7)
        # print(f"长度{len(text)}") 不是长度的问题
        # 以上是填充

        tr = b'\0' * 8
        to = b'\0' * 8
        r = b''
        o = b'\0' * 8
        for i in range(0, len(text), 8):
            o = xor(text[i:i + 8], tr)
            tr = xor(tea_code(o, self.secret_key), to)
            to = o
            r += tr
        return r

    def decrypt(self, text: bytes):  # v不可变
        l = len(text)
        prePlain = tea_decipher(text, self.secret_key)
        pos = (prePlain[0] & 0x07) + 2
        ret = prePlain
        preCrypt = text[0:8]
        for i in range(8, l, 8):
            x = xor(tea_decipher(xor(text[i:i + 8], prePlain), self.secret_key), preCrypt) # 跳过了前8个字节
            prePlain = xor(x, preCrypt)
            preCrypt = text[i:i + 8]
            ret += x
        if ret[-7:] != b'\0' * 7:
            return None
        return ret[pos + 1:-7]


if __name__ == '__main__':
    import time

    secret_key = bytes.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11')
    plaintext = '''下载地址：
        mega：https://mega.nz/folder/8SQUQDDA#B_pUPBIvCcfc2u4gpJvPyA
        Telegram Channel：
        csv https://t.me/mikuri520/669
        xlsx https://t.me/mikuri520/670
        SQL https://t.me/mikuri520/671'''
    QQ = TEA(secret_key)
    enc = QQ.encrypt(plaintext.encode())
    start = time.time()
    for i in range(10000):
        # plaintext = bytes(plaintext, encoding="utf-8")
        # print("".join(["%02x" % i for i in enc]))
        dec = QQ.decrypt(enc)
        # print(dec.decode())
    print(f"耗时{time.time() - start}")
