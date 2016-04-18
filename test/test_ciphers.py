# test_ciphers.py
#
# Copyright (C) 2006-2016 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
import unittest
from wolfcrypt.ciphers import *

class TestDes3(unittest.TestCase):
    key    = "0123456789abcdeffedeba987654321089abcdef01234567".decode("hex")
    IV     = "1234567890abcdef".decode("hex")
    plain  = "Now is the time for all "
    cipher = "43a0297ed184f80e8964843212d508981894157487127db0".decode("hex")


    def setUp(self):
        self.des3 = Des3.new(self.key, MODE_CBC, self.IV)


    def test_raises(self):
        # invalid construction
        self.assertRaises(ValueError, Des3)

        # invalid key length
        self.assertRaises(ValueError, Des3.new, "key", MODE_CBC, self.IV)

        # invalid mode
        self.assertRaises(ValueError, Des3.new, self.key, MODE_ECB, self.IV)

        # invalid iv length
        self.assertRaises(ValueError, Des3.new, self.key, MODE_CBC, "IV")

        # invalid data length
        self.assertRaises(ValueError, self.des3.encrypt, "foo")
        self.assertRaises(ValueError, self.des3.decrypt, "bar")


    def test_single_encryption(self):
        assert self.des3.encrypt(self.plain) == self.cipher


    def test_multi_encryption(self):
        result = ""
        segments = tuple(self.plain[i:i + Des3.block_size] \
            for i in range(0, len(self.plain), Des3.block_size))

        for segment in segments:
            result += self.des3.encrypt(segment)

        assert result == self.cipher


    def test_single_decryption(self):
        assert self.des3.decrypt(self.cipher) == self.plain


    def test_multi_decryption(self):
        result = ""
        segments = tuple(self.cipher[i:i + Des3.block_size] \
            for i in range(0, len(self.cipher), Des3.block_size))

        for segment in segments:
            result += self.des3.decrypt(segment)

        assert result == self.plain


class TestAes(unittest.TestCase):
    key    = "0123456789abcdef"
    IV     = "1234567890abcdef"
    plain  = "now is the time "
    cipher = "959492575f4281532ccc9d4677a233cb".decode("hex")


    def setUp(self):
        self.aes = Aes.new(self.key, MODE_CBC, self.IV)


    def test_raises(self):
        # invalid construction
        self.assertRaises(ValueError, Aes)

        # invalid key length
        self.assertRaises(ValueError, Aes.new, "key", MODE_CBC, self.IV)

        # invalid mode
        self.assertRaises(ValueError, Aes.new, self.key, MODE_ECB, self.IV)

        # invalid iv length
        self.assertRaises(ValueError, Aes.new, self.key, MODE_CBC, "IV")

        # invalid data length
        self.assertRaises(ValueError, self.aes.encrypt, "foo")
        self.assertRaises(ValueError, self.aes.decrypt, "bar")


    def test_single_encryption(self):
        assert self.aes.encrypt(self.plain) == self.cipher


    def test_multi_encryption(self):
        result = ""
        segments = tuple(self.plain[i:i + self.aes.block_size] \
            for i in range(0, len(self.plain), self.aes.block_size))

        for segment in segments:
            result += self.aes.encrypt(segment)

        assert result == self.cipher


    def test_single_decryption(self):
        assert self.aes.decrypt(self.cipher) == self.plain


    def test_multi_decryption(self):
        result = ""
        segments = tuple(self.cipher[i:i + self.aes.block_size] \
            for i in range(0, len(self.cipher), self.aes.block_size))

        for segment in segments:
            result += self.aes.decrypt(segment)

        assert result == self.plain
