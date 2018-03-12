# ciphers.py
#
# Copyright (C) 2006-2018 wolfSSL Inc.
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

# pylint: disable=no-member,no-name-in-module

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.utils import t2b
from wolfcrypt.random import Random

from wolfcrypt.exceptions import WolfCryptError


# key direction flags
_ENCRYPTION = 0
_DECRYPTION = 1


# feedback modes
MODE_ECB = 1  # Electronic Code Book
MODE_CBC = 2  # Cipher Block Chaining
MODE_CFB = 3  # Cipher Feedback
MODE_OFB = 5  # Output Feedback
MODE_CTR = 6  # Counter

_FEEDBACK_MODES = [MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR]


class _Cipher(object):
    """
    A **PEP 272: Block Encryption Algorithms** compliant
    **Symmetric Key Cipher**.
    """
    def __init__(self, key, mode, IV=None):
        if mode not in _FEEDBACK_MODES:
            raise ValueError("this mode is not supported")

        if mode == MODE_CBC:
            if IV is None:
                raise ValueError("this mode requires an 'IV' string")
        else:
            raise ValueError("this mode is not supported by this cipher")

        if self.key_size:
            if self.key_size != len(key):
                raise ValueError("key must be %d in length, not %d" %
                                 (self.key_size, len(key)))
        elif self._key_sizes:
            if len(key) not in self._key_sizes:
                raise ValueError("key must be %s in length, not %d" %
                                 (self._key_sizes, len(key)))
        elif not key:  # pragma: no cover
                raise ValueError("key must not be 0 in length")

        if IV is not None and len(IV) != self.block_size:
            raise ValueError("IV must be %d in length, not %d" %
                             (self.block_size, len(IV)))

        self._native_object = _ffi.new(self._native_type)
        self._enc = None
        self._dec = None
        self._key = t2b(key)

        if IV:
            self._IV = t2b(IV)
        else:  # pragma: no cover
            self._IV = _ffi.new("byte[%d]" % self.block_size)

    @classmethod
    def new(cls, key, mode, IV=None, **kwargs):  # pylint: disable=W0613
        """
        Returns a ciphering object, using the secret key contained in
        the string **key**, and using the feedback mode **mode**, which
        must be one of MODE_* defined in this module.

        If **mode** is MODE_CBC or MODE_CFB, **IV** must be provided and
        must be a string of the same length as the block size. Not
        providing a value of **IV** will result in a ValueError exception
        being raised.
        """
        return cls(key, mode, IV)

    def encrypt(self, string):
        """
        Encrypts a non-empty string, using the key-dependent data in
        the object, and with the appropriate feedback mode.
        
        The string's length must be an exact multiple of the algorithm's
        block size or, in CFB mode, of the segment size.
        
        Returns a string containing the ciphertext.
        """
        string = t2b(string)

        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        if self._enc is None:
            self._enc = _ffi.new(self._native_type)
            ret = self._set_key(_ENCRYPTION)
            if ret < 0:  # pragma: no cover
                raise WolfCryptError("Invalid key error (%d)" % ret)

        result = _ffi.new("byte[%d]" % len(string))
        ret = self._encrypt(result, string)
        if ret < 0:  # pragma: no cover
            raise WolfCryptError("Encryption error (%d)" % ret)

        return _ffi.buffer(result)[:]

    def decrypt(self, string):
        """
        Decrypts **string**, using the key-dependent data in the
        object and with the appropriate feedback mode.
        
        The string's length must be an exact multiple of the algorithm's
        block size or, in CFB mode, of the segment size.
        
        Returns a string containing the plaintext.
        """
        string = t2b(string)

        if not string or len(string) % self.block_size:
            raise ValueError(
                "string must be a multiple of %d in length" % self.block_size)

        if self._dec is None:
            self._dec = _ffi.new(self._native_type)
            ret = self._set_key(_DECRYPTION)
            if ret < 0:  # pragma: no cover
                raise WolfCryptError("Invalid key error (%d)" % ret)

        result = _ffi.new("byte[%d]" % len(string))
        ret = self._decrypt(result, string)
        if ret < 0:  # pragma: no cover
            raise WolfCryptError("Decryption error (%d)" % ret)

        return _ffi.buffer(result)[:]


class Aes(_Cipher):
    """
    The **Advanced Encryption Standard** (AES), a.k.a. Rijndael, is
    a symmetric-key cipher standardized by **NIST**.
    """
    block_size = 16
    key_size = None  # 16, 24, 32
    _key_sizes = [16, 24, 32]
    _native_type = "Aes *"

    def _set_key(self, direction):
        if direction == _ENCRYPTION:
            return _lib.wc_AesSetKey(
                self._enc, self._key, len(self._key), self._IV, _ENCRYPTION)

        return _lib.wc_AesSetKey(
            self._dec, self._key, len(self._key), self._IV, _DECRYPTION)

    def _encrypt(self, destination, source):
        return _lib.wc_AesCbcEncrypt(self._enc, destination,
                                     source, len(source))

    def _decrypt(self, destination, source):
        return _lib.wc_AesCbcDecrypt(self._dec, destination,
                                     source, len(source))


class Des3(_Cipher):
    """
    **Triple DES** (3DES) is the common name for the **Triple Data
    Encryption Algorithm** (TDEA or Triple DEA) symmetric-key block
    cipher, which applies the **Data Encryption Standard** (DES)
    cipher algorithm three times to each data block.
    """
    block_size = 8
    key_size = 24
    _native_type = "Des3 *"

    def _set_key(self, direction):
        if direction == _ENCRYPTION:
            return _lib.wc_Des3_SetKey(self._enc, self._key,
                                       self._IV, _ENCRYPTION)

        return _lib.wc_Des3_SetKey(self._dec, self._key,
                                   self._IV, _DECRYPTION)

    def _encrypt(self, destination, source):
        return _lib.wc_Des3_CbcEncrypt(self._enc, destination,
                                       source, len(source))

    def _decrypt(self, destination, source):
        return _lib.wc_Des3_CbcDecrypt(self._dec, destination,
                                       source, len(source))


class _Rsa(object):  # pylint: disable=too-few-public-methods
    RSA_MIN_PAD_SIZE = 11

    def __init__(self):
        self.native_object = _ffi.new("RsaKey *")
        ret = _lib.wc_InitRsaKey(self.native_object, _ffi.NULL)
        if ret < 0:  # pragma: no cover
            raise WolfCryptError("Invalid key error (%d)" % ret)

        self._random = Random()
        ret = _lib.wc_RsaSetRNG(self.native_object, self._random.native_object)
        if ret < 0:  # pragma: no cover
            raise WolfCryptError("Key initialization error (%d)" % ret)

    def __del__(self):
        if self.native_object:
            _lib.wc_FreeRsaKey(self.native_object)


class RsaPublic(_Rsa):
    def __init__(self, key):
        key = t2b(key)

        _Rsa.__init__(self)

        idx = _ffi.new("word32*")
        idx[0] = 0

        ret = _lib.wc_RsaPublicKeyDecode(key, idx,
                                         self.native_object, len(key))
        if ret < 0:
            raise WolfCryptError("Invalid key error (%d)" % ret)

        self.output_size = _lib.wc_RsaEncryptSize(self.native_object)
        if self.output_size <= 0:  # pragma: no cover
            raise WolfCryptError("Invalid key error (%d)" % self.output_size)

    def encrypt(self, plaintext):
        """
        Encrypts **plaintext**, using the public key data in the
        object. The plaintext's length must not be greater than:

            **self.output_size - self.RSA_MIN_PAD_SIZE**

        Returns a string containing the ciphertext.
        """

        plaintext = t2b(plaintext)
        ciphertext = _ffi.new("byte[%d]" % self.output_size)

        ret = _lib.wc_RsaPublicEncrypt(plaintext, len(plaintext),
                                       ciphertext, self.output_size,
                                       self.native_object,
                                       self._random.native_object)

        if ret != self.output_size:  # pragma: no cover
            raise WolfCryptError("Encryption error (%d)" % ret)

        return _ffi.buffer(ciphertext)[:]

    def verify(self, signature):
        """
        Verifies **signature**, using the public key data in the
        object. The signature's length must be equal to:

            **self.output_size**

        Returns a string containing the plaintext.
        """
        signature = t2b(signature)
        plaintext = _ffi.new("byte[%d]" % self.output_size)

        ret = _lib.wc_RsaSSL_Verify(signature, len(signature),
                                    plaintext, self.output_size,
                                    self.native_object)

        if ret < 0:  # pragma: no cover
            raise WolfCryptError("Verify error (%d)" % ret)

        return _ffi.buffer(plaintext, ret)[:]


class RsaPrivate(RsaPublic):
    def __init__(self, key):  # pylint: disable=super-init-not-called
        key = t2b(key)

        _Rsa.__init__(self)  # pylint: disable=non-parent-init-called

        idx = _ffi.new("word32*")
        idx[0] = 0

        ret = _lib.wc_RsaPrivateKeyDecode(key, idx,
                                          self.native_object, len(key))
        if ret < 0:
            raise WolfCryptError("Invalid key error (%d)" % ret)

        self.output_size = _lib.wc_RsaEncryptSize(self.native_object)
        if self.output_size <= 0:  # pragma: no cover
            raise WolfCryptError("Invalid key error (%d)" % self.output_size)

    def decrypt(self, ciphertext):
        """
        Decrypts **ciphertext**, using the private key data in the
        object. The ciphertext's length must be equal to:

            **self.output_size**

        Returns a string containing the plaintext.
        """
        ciphertext = t2b(ciphertext)
        plaintext = _ffi.new("byte[%d]" % self.output_size)

        ret = _lib.wc_RsaPrivateDecrypt(ciphertext, len(ciphertext),
                                        plaintext, self.output_size,
                                        self.native_object)

        if ret < 0:  # pragma: no cover
            raise WolfCryptError("Decryption error (%d)" % ret)

        return _ffi.buffer(plaintext, ret)[:]

    def sign(self, plaintext):
        """
        Signs **plaintext**, using the private key data in the object.
        The plaintext's length must not be greater than:

            **self.output_size - self.RSA_MIN_PAD_SIZE**

        Returns a string containing the signature.
        """
        plaintext = t2b(plaintext)
        signature = _ffi.new("byte[%d]" % self.output_size)

        ret = _lib.wc_RsaSSL_Sign(plaintext, len(plaintext),
                                  signature, self.output_size,
                                  self.native_object,
                                  self._random.native_object)

        if ret != self.output_size:  # pragma: no cover
            raise WolfCryptError("Signature error (%d)" % ret)

        return _ffi.buffer(signature, self.output_size)[:]


class _Ecc(object):  # pylint: disable=too-few-public-methods
    def __init__(self):
        self.native_object = _ffi.new("ecc_key *")
        ret = _lib.wc_ecc_init(self.native_object)
        if ret < 0:  # pragma: no cover
            raise WolfCryptError("Invalid key error (%d)" % ret)

    def __del__(self):
        if self.native_object:
            _lib.wc_ecc_free(self.native_object)

    @property
    def size(self):
        return _lib.wc_ecc_size(self.native_object)

    @property
    def max_signature_size(self):
        return _lib.wc_ecc_sig_size(self.native_object)


class EccPublic(_Ecc):
    def __init__(self, key=None):
        _Ecc.__init__(self)

        if key:
            self.decode_key(key)

    def decode_key(self, key):
        """
        Decodes an ECC public key from an ASN sequence.
        """
        key = t2b(key)

        idx = _ffi.new("word32*")
        idx[0] = 0

        ret = _lib.wc_EccPublicKeyDecode(key, idx,
                                         self.native_object, len(key))
        if ret < 0:
            raise WolfCryptError("Key decode error (%d)" % ret)
        if self.size <= 0:  # pragma: no cover
            raise WolfCryptError("Key decode error (%d)" % self.size)
        if self.max_signature_size <= 0:  # pragma: no cover
            raise WolfCryptError(
                "Key decode error (%d)" % self.max_signature_size)

    def encode_key(self, with_curve=True):
        """
        Encodes the ECC public key in an ASN sequence.

        Returns the encoded key.
        """
        key = _ffi.new("byte[%d]" % (self.size * 4))

        ret = _lib.wc_EccPublicKeyToDer(self.native_object, key, len(key),
                                        with_curve)
        if ret <= 0:  # pragma: no cover
            raise WolfCryptError("Key encode error (%d)" % ret)

        return _ffi.buffer(key, ret)[:]

    def import_x963(self, x963):
        """
        Imports an ECC public key in ANSI X9.63 format.
        """
        ret = _lib.wc_ecc_import_x963(x963, len(x963), self.native_object)
        if ret != 0:
            raise WolfCryptError("x963 import error (%d)" % ret)

    def export_x963(self):
        """
        Exports the public key data of the object in ANSI X9.63 format.

        Returns the exported key.
        """
        x963 = _ffi.new("byte[%d]" % (self.size * 4))
        x963_size = _ffi.new("word32[1]")
        x963_size[0] = self.size * 4

        ret = _lib.wc_ecc_export_x963(self.native_object, x963, x963_size)
        if ret != 0:  # pragma: no cover
            raise WolfCryptError("x963 export error (%d)" % ret) 

        return _ffi.buffer(x963, x963_size[0])[:]

    def verify(self, signature, data):
        """
        Verifies **signature**, using the public key data in the object.

        Returns **True** in case of a valid signature, otherwise **False**.
        """
        data = t2b(data)
        status = _ffi.new("int[1]")

        ret = _lib.wc_ecc_verify_hash(signature, len(signature),
                                      data, len(data),
                                      status, self.native_object)

        if ret < 0:
            raise WolfCryptError("Verify error (%d)" % ret)

        return status[0] == 1


class EccPrivate(EccPublic):
    @classmethod
    def make_key(cls, size, rng=Random()):
        """
        Generates a new key pair of desired length **size**.
        """
        ecc = cls()

        ret = _lib.wc_ecc_make_key(rng.native_object, size, ecc.native_object)
        if ret < 0:
            raise WolfCryptError("Key generation error (%d)" % ret)

        return ecc

    def decode_key(self, key):
        """
        Decodes an ECC private key from an ASN sequence.
        """
        key = t2b(key)

        idx = _ffi.new("word32*")
        idx[0] = 0

        ret = _lib.wc_EccPrivateKeyDecode(key, idx,
                                          self.native_object, len(key))
        if ret < 0:
            raise WolfCryptError("Key decode error (%d)" % ret)
        if self.size <= 0:  # pragma: no cover
            raise WolfCryptError("Key decode error (%d)" % self.size)
        if self.max_signature_size <= 0:  # pragma: no cover
            raise WolfCryptError(
                "Key decode error (%d)" % self.max_signature_size)

    def encode_key(self):
        """
        Encodes the ECC private key in an ASN sequence.

        Returns the encoded key.
        """
        key = _ffi.new("byte[%d]" % (self.size * 4))

        ret = _lib.wc_EccKeyToDer(self.native_object, key, len(key))
        if ret <= 0:  # pragma: no cover
            raise WolfCryptError("Key encode error (%d)" % ret)

        return _ffi.buffer(key, ret)[:]

    def shared_secret(self, peer):
        """
        Generates a new secret key using the private key data in the object
        and the peer's public key.

        Returns the shared secret.
        """
        shared_secret = _ffi.new("byte[%d]" % self.max_signature_size)
        secret_size = _ffi.new("word32[1]")
        secret_size[0] = self.max_signature_size

        ret = _lib.wc_ecc_shared_secret(self.native_object,
                                        peer.native_object,
                                        shared_secret, secret_size)

        if ret != 0:  # pragma: no cover
            raise WolfCryptError("Shared secret error (%d)" % ret)

        return _ffi.buffer(shared_secret, secret_size[0])[:]

    def sign(self, plaintext, rng=Random()):
        """
        Signs **plaintext**, using the private key data in the object.

        Returns the signature.
        """
        plaintext = t2b(plaintext)
        signature = _ffi.new("byte[%d]" % self.max_signature_size)

        signature_size = _ffi.new("word32[1]")
        signature_size[0] = self.max_signature_size

        ret = _lib.wc_ecc_sign_hash(plaintext, len(plaintext),
                                    signature, signature_size,
                                    rng.native_object,
                                    self.native_object)

        if ret != 0:  # pragma: no cover
            raise WolfCryptError("Signature error (%d)" % ret)

        return _ffi.buffer(signature, signature_size[0])[:]
