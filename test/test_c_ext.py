# -*- coding: utf-8 -*-
import unittest

from pytea import TEA, PYTEA


class TestC(unittest.TestCase):
    def setUp(self) -> None:
        self.secret_key = bytes.fromhex('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11')
        self.pytea = PYTEA(self.secret_key)
        self.ctea = TEA(self.secret_key)

    def test_key(self):
        self.assertEqual(self.ctea.secret_key, self.pytea.secret_key)
        self.assertEqual(self.ctea.encrypt_times, 16)

    def test_encrypt(self):
        self.assertEqual(self.ctea.encrypt("123456".encode()), self.pytea.encrypt("123456".encode()))

    def test_decrypt(self):
        data = bytes.fromhex(
            "f9ab46fad61dc9af4bac4e690a6470dbf8365f870525927da3bec1530bfa8b7edaaec7fbdc1b385280f01bdf595d7b2ced0c484259bc629a3c3aa39c135535345e7938dd2503736f3745d8e12fa20b325ccf551f11921aaf80c68b9a26155654e3c0b83d883a1a1e9a2375c5c0d2c2b128d3ad0aca856c0eeb4efa815c3a8032ec7ed112d1b5a9d1da3c2303d4d7d4ec494b516f60b8ee22f14414d1bc2c3c704d869ec35c546f3e0bae5c467608fd24043528e94e31fa2584b2fc6b12f87a3463515f99025c5fd1dd245111306bd1d8")
        self.assertEqual(self.ctea.decrypt(data), self.pytea.decrypt(data))


if __name__ == "__main__":
    unittest.main()
