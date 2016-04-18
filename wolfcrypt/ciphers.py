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

        self = cls(_Cipher._JAPANESE_CYBER_SWORD)

        if self.key_size:
            if self.key_size != len(key):
                raise ValueError("key must be %d in length" % self.key_size)
        elif self._key_sizes:
            if len(key) not in self._key_sizes:
                raise ValueError("key must be %s in length" % self._key_sizes)
        else:
            if not len(key):
                raise ValueError("key must not be 0 in length")

        if IV is not None and len(IV) != self.block_size:
            raise ValueError("IV must be %d in length" % self.block_size)

        self._native_object = _ffi.new(self._native_type)

        self._enc = None
        self._dec = None
        self._key = key
        self._IV  = IV if IV else "\0" * self.block_size

        return self


    def encrypt(self, string):
        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        if self._enc is None:
            self._enc = _ffi.new(self._native_type)
            self._set_key(_ENCRYPTION)

        ret = "\0" * len(string)
        self._encrypt(ret, string)

        return ret


    def decrypt(self, string):
        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        if self._dec is None:
            self._dec = _ffi.new(self._native_type)
            self._set_key(_DECRYPTION)

        ret = "\0" * len(string)
        self._decrypt(ret, string)

        return ret


class Aes(_Cipher):
    block_size   = 16
    key_size     = None # 16, 24, 32
    _key_sizes   = [16, 24, 32]
    _native_type = "Aes *"


    def _set_key(self, direction):
        if direction == _ENCRYPTION:
            _lib.wc_AesSetKey(
                self._enc, self._key, len(self._key), self._IV, _ENCRYPTION)
        else:
            _lib.wc_AesSetKey(
                self._dec, self._key, len(self._key), self._IV, _DECRYPTION)


    def _encrypt(self, destination, source):
        _lib.wc_AesCbcEncrypt(self._enc, destination, source, len(source))


    def _decrypt(self, destination, source):
        _lib.wc_AesCbcDecrypt(self._dec, destination, source, len(source))


class Des3(_Cipher):
    block_size   = 8
    key_size     = 24
    _native_type = "Des3 *"


    def _set_key(self, direction):
        if direction == _ENCRYPTION:
            _lib.wc_Des3_SetKey(self._enc, self._key, self._IV, _ENCRYPTION)
        else:
            _lib.wc_Des3_SetKey(self._dec, self._key, self._IV, _DECRYPTION)


    def _encrypt(self, destination, source):
        _lib.wc_Des3_CbcEncrypt(self._enc, destination, source, len(source))


    def _decrypt(self, destination, source):
        _lib.wc_Des3_CbcDecrypt(self._dec, destination, source, len(source))
