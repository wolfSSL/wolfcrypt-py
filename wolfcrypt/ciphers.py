# ciphers.py
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
from wolfcrypt._ciphers import ffi
from wolfcrypt._ciphers import lib

MODE_ECB = 1 # Electronic Code Book
MODE_CBC = 2 # Cipher Block Chaining
MODE_CFB = 3 # Cipher Feedback
MODE_OFB = 5 # Output Feedback
MODE_CTR = 6 # Counter

class Cipher(object):
    # Magic object that protects against constructors.
    _JAPANESE_CYBER_SWORD = object()


    def __init__(self, token=""):
        if token is not self._JAPANESE_CYBER_SWORD:
            # PEP 272 -- API for Block Encryption Algorithms v1.0
            raise ValueError("don't construct directly, use new([string])")


    @classmethod
    def new(cls, key, mode, IV=None, **kwargs):
        if mode != MODE_CBC:
            raise ValueError("this mode is not supported by this cipher")

        obj = cls(Cipher._JAPANESE_CYBER_SWORD)

        if len(key) != obj.key_size:
            raise ValueError("key must be %d in length" % obj.key_size)

        if IV is not None and len(IV) != obj.block_size:
            raise ValueError("IV must be %d in length" % obj.block_size)

        obj._native_object = ffi.new(obj._native_type)

        obj._key = key
        obj._IV  = IV

        return obj


    def encrypt(self, string):
        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        cipher = ffi.new(self._native_type)
        ret    = "\0" * len(string)

        self._set_key(cipher, self._ENCRYPTION)
        self._encrypt(cipher, ret, string)

        return ret


    def decrypt(self, string):
        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        cipher = ffi.new(self._native_type)
        ret    = "\0" * len(string)

        self._set_key(cipher, self._DECRYPTION)
        self._decrypt(cipher, ret, string)

        return ret


class Des3(Cipher):
    key_size     = 24
    block_size   = 8
    _native_type = "Des3 *"

    # key direction flags
    _ENCRYPTION  = 0
    _DECRYPTION  = 1


    def _set_key(self, native_object, direction):
        lib.wc_Des3_SetKey(native_object, self._key, self._IV, direction)


    def _encrypt(self, native_object, destination, source):
        lib.wc_Des3_CbcEncrypt(native_object, destination, source, len(source))


    def _decrypt(self, native_object, destination, source):
        lib.wc_Des3_CbcDecrypt(native_object, destination, source, len(source))
