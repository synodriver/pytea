# -*- coding: utf-8 -*-
import unittest
import sys

sys.path.append("../")

from pytea import TEA, PYTEA, check_pymalloc
from pytea.pytea import tea_code, tea_decipher


class TestC(unittest.TestCase):
    def setUp(self) -> None:
        self.secret_key = bytes.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 22')
        self.pytea = PYTEA(bytes.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 22'))
        self.ctea = TEA(bytearray.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 22'))

    def test_encode_long(self):
        test_data = '''下载地址：
mega：https://mega.nz/folder/8SQUQDDA#B_pUPBIvCcfc2u4gpJvPyA
Telegram Channel：
csv https://t.me/mikuri520/669
xlsx https://t.me/mikuri520/670
SQL https://t.me/mikuri520/671'''
        pytea = PYTEA(bytes.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11'))
        ctea = TEA(bytes.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11'))
        self.assertEqual(ctea.encrypt(test_data.encode()), pytea.encrypt(test_data.encode()))

    def test_py_long(self):
        pytea = PYTEA(bytes.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11'))
        ctea = TEA(bytes.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11'))
        data = pytea.decrypt(bytes.fromhex(
            "f9ab46fad61dc9af4bac4e690a6470dbf8365f870525927da3bec1530bfa8b7edaaec7fbdc1b385280f01bdf595d7b2ced0c484259bc629a3c3aa39c135535345e7938dd2503736f3745d8e12fa20b325ccf551f11921aaf80c68b9a26155654e3c0b83d883a1a1e9a2375c5c0d2c2b128d3ad0aca856c0eeb4efa815c3a8032ec7ed112d1b5a9d1da3c2303d4d7d4ec494b516f60b8ee22f14414d1bc2c3c704d869ec35c546f3e0bae5c467608fd24043528e94e31fa2584b2fc6b12f87a3463515f99025c5fd1dd245111306bd1d8"))
        data_c = ctea.decrypt(bytes.fromhex(
            "f9ab46fad61dc9af4bac4e690a6470dbf8365f870525927da3bec1530bfa8b7edaaec7fbdc1b385280f01bdf595d7b2ced0c484259bc629a3c3aa39c135535345e7938dd2503736f3745d8e12fa20b325ccf551f11921aaf80c68b9a26155654e3c0b83d883a1a1e9a2375c5c0d2c2b128d3ad0aca856c0eeb4efa815c3a8032ec7ed112d1b5a9d1da3c2303d4d7d4ec494b516f60b8ee22f14414d1bc2c3c704d869ec35c546f3e0bae5c467608fd24043528e94e31fa2584b2fc6b12f87a3463515f99025c5fd1dd245111306bd1d8"))

        self.assertEqual(data.decode(), '''下载地址：
mega：https://mega.nz/folder/8SQUQDDA#B_pUPBIvCcfc2u4gpJvPyA
Telegram Channel：
csv https://t.me/mikuri520/669
xlsx https://t.me/mikuri520/670
SQL https://t.me/mikuri520/671''')
        self.assertEqual(data, data_c)

    def test_key(self):
        pass
        data_py = self.pytea.secret_key
        data_c = self.ctea.key
        self.assertEqual(data_c, data_py)
        self.assertEqual(self.ctea.encrypt_times, 16)

    def test_encrypt_group(self):
        data_c = self.ctea.encrypt_group(bytes.fromhex('f8dcdc3132333435'))
        data_py = tea_code(bytes.fromhex('f8dcdc3132333435'),
                           self.secret_key)  # (286331153, 286331153, 286331153, 286331170)
        # v0 4175223857 v1 842216501  执行和 v0 2419188727 v1 2979123055
        # print(data_c, data_py)
        self.assertEqual(data_c, data_py)
        pass

    def test_decrypt_group(self):
        data_c = self.ctea.decrypt_group(bytes.fromhex('9031e3f7b191cf6f'))  # v0 2419188727 v1 2979123055
        data_py = tea_decipher(bytes.fromhex('9031e3f7b191cf6f'),
                               self.secret_key)  # key (286331153, 286331153, 286331153, 286331170)
        # v0 4175223857 v1 842216501
        self.assertEqual(data_c, data_py)
        pass

    def test_encrypt(self):  # 'f8dcdc3132333435' 'b5dc08edb3276052
        test_data = "0"
        for i in range(100):
            test_data += str(i)
            data_c = self.ctea.encrypt(bytearray(test_data.encode()))
            data_py = self.pytea.encrypt(test_data.encode())
            self.assertEqual(data_c, data_py, msg=f"fail origin {test_data} ctea{data_c} pytea{data_py}")
        # text的前8字节应该的样子 v0 4175223857 v1 842216501
        # 第一轮加密的v0 v1 2419188727 2979123055

    def test_decrypt(self):  # todo 当前进度在此
        data = bytes.fromhex('9031e3f7b191cf6f7586b3d0a1d690aa')
        data_py = self.pytea.decrypt(data)  # 完整的16字节 4175223857 842216501 905969664 0   pos=2
        data_c = self.ctea.decrypt(bytearray(data))

        self.assertEqual(data_c, data_py)

    def test_loginpack(self):
        ctea = TEA(bytes(16))
        with open("data.txt") as f:
            data = bytes.fromhex(f.read().strip())
        ans = ctea.decrypt(data)
        self.assertEqual(len(ans), 1671)
        pass

    def test_veryloing(self):
        data_py = self.pytea.encrypt(bytes(4096))
        data_c = self.ctea.encrypt(bytes(4096))
        self.assertEqual(data_c, data_py)
        self.assertEqual(self.pytea.encrypt(data_c), self.pytea.encrypt(data_py))

    def test_two_instance(self):
        ctea = TEA(bytes(16))
        self.assertEqual(ctea.key, bytes(16))
        self.assertEqual(self.ctea.key, self.secret_key)

    def test_2_ctea(self):
        ctea1 = TEA(bytes(16))
        test_data = "hhhh".encode()
        encoded = ctea1.encrypt(test_data)
        ctea2 = TEA(bytes.fromhex('11' * 16))
        self.assertEqual(ctea1.decrypt(encoded), test_data)

    def test_pymalloc(self):
        self.assertEqual(check_pymalloc(), True)


if __name__ == "__main__":
    unittest.main()
