# -*- coding: utf-8 -*-
from copy import deepcopy

from pytea import PYTEA
from pytea import TEA

if __name__ == '__main__':
    import time

    secret_key = bytes.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11')
    plaintext = '''下载地址：
        mega：https://mega.nz/folder/8SQUQDDA#B_pUPBIvCcfc2u4gpJvPyA
        Telegram Channel：
        csv https://t.me/mikuri520/669
        xlsx https://t.me/mikuri520/670
        SQL https://t.me/mikuri520/671'''
    QQ = PYTEA(secret_key)
    CQQ = TEA(deepcopy(secret_key))

    enc = QQ.encrypt(plaintext.encode())

    start = time.time()
    for i in range(1000):
        # plaintext = bytes(plaintext, encoding="utf-8")
        # print("".join(["%02x" % i for i in enc]))
        dec = QQ.decrypt(enc)
        QQ.encrypt(dec)
        # print(dec.decode())
    print(f"py耗时{(pytime:=time.time() - start)}")
    start = time.time()
    for i in range(1000):
        # plaintext = bytes(plaintext, encoding="utf-8")
        # print("".join(["%02x" % i for i in enc]))
        dec = CQQ.decrypt(enc)
        CQQ.encrypt(dec)
        # print(dec.decode())
    print(f"c耗时{(ctime:=time.time() - start)}")
    print(f"chaju {pytime/ctime}")