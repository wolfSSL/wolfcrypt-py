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
from wolfcrypt._ciphers import ffi as _ffi
from wolfcrypt._ciphers import lib as _lib


# key direction flags
_ENCRYPTION  = 0
_DECRYPTION  = 1


# feedback modes
MODE_ECB = 1 # Electronic Code Book
MODE_CBC = 2 # Cipher Block Chaining
MODE_CFB = 3 # Cipher Feedback
MODE_OFB = 5 # Output Feedback
MODE_CTR = 6 # Counter

_FEEDBACK_MODES = [MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR]


class _Cipher(object):
    # Magic object that protects against constructors.
    _JAPANESE_CYBER_SWORD = object()


    def __init__(self, token=""):
        if token is not self._JAPANESE_CYBER_SWORD:
            # PEP 272 -- API for Block Encryption Algorithms v1.0
            raise ValueError("don't construct directly, use new([string])")


    @classmethod
    def new(cls, key, mode, IV=None, **kwargs):
        if mode not in _FEEDBACK_MODES:
            raise ValueError("this mode is not supported")
        if mode != MODE_CBC:
            raise ValueError("this mode is not supported by this cipher")

        obj = cls(Cipher._JAPANESE_CYBER_SWORD)

        if obj.key_size:
            if obj.key_size != len(key):
                raise ValueError("key must be %d in length" % obj.key_size)
        elif obj._key_sizes:
            if len(key) not in obj._key_sizes:
                raise ValueError("key must be %s in length" % obj._key_sizes)
        else:
            if not len(key):
                raise ValueError("key must not be 0 in length")

        if IV is not None and len(IV) != obj.block_size:
            raise ValueError("IV must be %d in length" % obj.block_size)

        obj._native_object = _ffi.new(obj._native_type)

        obj._key = key
        obj._IV  = IV if IV else "\0" * obj.block_size

        return obj


    def encrypt(self, string):
        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        cipher = _ffi.new(self._native_type)
        ret    = "\0" * len(string)

        self._set_key(cipher, _ENCRYPTION)
        self._encrypt(cipher, ret, string)

        return ret


    def decrypt(self, string):
        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        cipher = _ffi.new(self._native_type)
        ret    = "\0" * len(string)

        self._set_key(cipher, _DECRYPTION)
        self._decrypt(cipher, ret, string)

        return ret


class Aes(_Cipher):
    key_size     = None # 16, 24, 32
    _key_sizes   = [16, 24, 32]
    block_size   = 16
    _native_type = "Aes *"


    def _set_key(self, native_object, direction):
        _lib.wc_AesSetKey(
            native_object, self._key, len(self._key), self._IV, direction)


    def _encrypt(self, native_object, destination, source):
        _lib.wc_AesCbcEncrypt(native_object, destination, source, len(source))


    def _decrypt(self, native_object, destination, source):
        _lib.wc_AesCbcDecrypt(native_object, destination, source, len(source))


class Des3(_Cipher):
    key_size     = 24
    block_size   = 8
    _native_type = "Des3 *"


    def _set_key(self, native_object, direction):
        _lib.wc_Des3_SetKey(native_object, self._key, self._IV, direction)


    def _encrypt(self, native_object, destination, source):
        _lib.wc_Des3_CbcEncrypt(native_object, destination, source, len(source))


    def _decrypt(self, native_object, destination, source):
        _lib.wc_Des3_CbcDecrypt(native_object, destination, source, len(source))
