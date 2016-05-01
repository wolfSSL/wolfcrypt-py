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
from wolfcrypt._ffi   import ffi as _ffi
from wolfcrypt._ffi   import lib as _lib
from wolfcrypt.utils  import _t2b
from wolfcrypt.random import Random

from wolfcrypt.exceptions import *


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
    def __init__(self, key, mode, IV=None):
        if mode not in _FEEDBACK_MODES:
            raise ValueError("this mode is not supported")

        if mode != MODE_CBC:
            raise ValueError("this mode is not supported by this cipher")

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
        self._key = _t2b(key)

        if IV:
            self._IV = _t2b(IV)
        else:
            self._IV = _t2b("\0" * self.block_size)


    @classmethod
    def new(cls, key, mode, IV=None, **kwargs):
        # PEP 272 -- API for Block Encryption Algorithms
        return cls(key, mode, IV)


    def encrypt(self, string):
        string = _t2b(string)

        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        if self._enc is None:
            self._enc = _ffi.new(self._native_type)
            ret = self._set_key(_ENCRYPTION)
            if ret < 0:
                raise WolfCryptError("Invalid key error (%d)" % ret)

        result = _t2b("\0" * len(string))
        ret = self._encrypt(result, string)
        if ret < 0:
            raise WolfCryptError("Encryption error (%d)" % ret)

        return result


    def decrypt(self, string):
        string = _t2b(string)

        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        if self._dec is None:
            self._dec = _ffi.new(self._native_type)
            ret = self._set_key(_DECRYPTION)
            if ret < 0:
                raise WolfCryptError("Invalid key error (%d)" % ret)

        result = _t2b("\0" * len(string))
        ret = self._decrypt(result, string)
        if ret < 0:
            raise WolfCryptError("Decryption error (%d)" % ret)

        return result


class Aes(_Cipher):
    block_size   = 16
    key_size     = None # 16, 24, 32
    _key_sizes   = [16, 24, 32]
    _native_type = "Aes *"


    def _set_key(self, direction):
        if direction == _ENCRYPTION:
            return _lib.wc_AesSetKey(
                self._enc, self._key, len(self._key), self._IV, _ENCRYPTION)
        else:
            return _lib.wc_AesSetKey(
                self._dec, self._key, len(self._key), self._IV, _DECRYPTION)


    def _encrypt(self, destination, source):
        return _lib.wc_AesCbcEncrypt(self._enc, destination, source,len(source))


    def _decrypt(self, destination, source):
        return _lib.wc_AesCbcDecrypt(self._dec, destination, source,len(source))


class Des3(_Cipher):
    block_size   = 8
    key_size     = 24
    _native_type = "Des3 *"


    def _set_key(self, direction):
        if direction == _ENCRYPTION:
            return _lib.wc_Des3_SetKey(self._enc,self._key,self._IV,_ENCRYPTION)
        else:
            return _lib.wc_Des3_SetKey(self._dec,self._key,self._IV,_DECRYPTION)


    def _encrypt(self, destination, source):
        return _lib.wc_Des3_CbcEncrypt(self._enc,destination,source,len(source))


    def _decrypt(self, destination, source):
        return _lib.wc_Des3_CbcDecrypt(self._dec,destination,source,len(source))


class _Rsa(object):
    def __init__(self):
        self.native_object = _ffi.new("RsaKey *")
        ret = _lib.wc_InitRsaKey(self.native_object, _ffi.NULL)
        if ret < 0:
            raise WolfCryptError("Invalid key error (%d)" % ret)

        self._random = Random()


    def __del__(self):
        if self.native_object:
            _lib.wc_FreeRsaKey(self.native_object)


class RsaPublic(_Rsa):
    def __init__(self, key):
        key = _t2b(key)

        _Rsa.__init__(self)

        idx = _ffi.new("word32*")
        idx[0] = 0

        ret = _lib.wc_RsaPublicKeyDecode(key, idx, self.native_object, len(key))
        if ret < 0:
            raise WolfCryptError("Invalid key error (%d)" % ret)

        self.output_size = _lib.wc_RsaEncryptSize(self.native_object)
        if self.output_size <= 0:
            raise WolfCryptError("Invalid key error (%d)" % self.output_size)


    def encrypt(self, plaintext):
        plaintext = _t2b(plaintext)
        ciphertext = _t2b("\0" * self.output_size)

        ret = _lib.wc_RsaPublicEncrypt(plaintext, len(plaintext),
                                       ciphertext, len(ciphertext),
                                       self.native_object,
                                       self._random.native_object)

        if ret != self.output_size:
            raise WolfCryptError("Encryption error (%d)" % ret)

        return ciphertext


    def verify(self, signature):
        signature = _t2b(signature)
        plaintext = _t2b("\0" * self.output_size)

        ret = _lib.wc_RsaSSL_Verify(signature, len(signature),
                                    plaintext, len(plaintext),
                                    self.native_object)

        if ret < 0:
            raise WolfCryptError("Verify error (%d)" % ret)

        return plaintext[:ret]


class RsaPrivate(RsaPublic):
    def __init__(self, key):
        key = _t2b(key)

        _Rsa.__init__(self)

        idx = _ffi.new("word32*")
        idx[0] = 0

        ret = _lib.wc_RsaPrivateKeyDecode(key, idx, self.native_object,len(key))
        if ret < 0:
            raise WolfCryptError("Invalid key error (%d)" % ret)

        self.output_size = _lib.wc_RsaEncryptSize(self.native_object)
        if self.output_size <= 0:
            raise WolfCryptError("Invalid key error (%d)" % self.output_size)


    def decrypt(self, ciphertext):
        ciphertext = _t2b(ciphertext)
        plaintext = _t2b("\0" * self.output_size)

        ret = _lib.wc_RsaPrivateDecrypt(ciphertext, len(ciphertext),
                                        plaintext, len(plaintext),
                                        self.native_object)

        if ret < 0:
            raise WolfCryptError("Decryption error (%d)" % ret)

        return plaintext[:ret]


    def sign(self, plaintext):
        plaintext = _t2b(plaintext)
        signature = _t2b("\0" * self.output_size)

        ret = _lib.wc_RsaSSL_Sign(plaintext, len(plaintext),
                                  signature, len(signature),
                                  self.native_object,
                                  self._random.native_object)

        if ret != self.output_size:
            raise WolfCryptError("Signature error (%d)" % ret)

        return signature
