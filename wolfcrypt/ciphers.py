# ciphers.py
#
# Copyright (C) 2006-2025 wolfSSL Inc.
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

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from enum import IntEnum

from typing_extensions import override
from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.exceptions import WolfCryptError, WolfCryptApiError
from wolfcrypt.hashes import hash_type_to_cls
from wolfcrypt.random import Random
from wolfcrypt.utils import BytesOrStr, t2b
from .wc_types import SupportsRsaSign, SupportsRsaVerify

if _lib.ASN_ENABLED:
    from wolfcrypt.asn import pem_to_der  # ty: ignore[possibly-missing-import]


# key direction flags
_ENCRYPTION = 0
_DECRYPTION = 1


# feedback modes
MODE_ECB = 1  # Electronic Code Book
MODE_CBC = 2  # Cipher Block Chaining
MODE_CFB = 3  # Cipher Feedback
MODE_OFB = 5  # Output Feedback
MODE_CTR = 6  # Counter

# Only the modes the generic _Cipher actually supports. MODE_ECB/MODE_CFB/
# MODE_OFB are defined above for PEP 272 completeness but are not implemented.
_FEEDBACK_MODES = [MODE_CBC, MODE_CTR]

# ECC curve id
ECC_CURVE_INVALID = -1
ECC_CURVE_DEF = 0

# NIST Prime Curves
ECC_SECP192R1 = 1
ECC_PRIME192V2 = 2
ECC_PRIME192V3 = 3
ECC_PRIME239V1 = 4
ECC_PRIME239V2 = 5
ECC_PRIME239V3 = 6
ECC_SECP256R1 = 7

# SECP Curves
ECC_SECP112R1 = 8
ECC_SECP112R2 = 9
ECC_SECP128R1 = 10
ECC_SECP128R2 = 11
ECC_SECP160R1 = 12
ECC_SECP160R2 = 13
ECC_SECP224R1 = 14
ECC_SECP384R1 = 15
ECC_SECP521R1 = 16

# Koblitz
ECC_SECP160K1 = 17
ECC_SECP192K1 = 18
ECC_SECP224K1 = 19
ECC_SECP256K1 = 20

# Brainpool Curves
ECC_BRAINPOOLP160R1 = 21
ECC_BRAINPOOLP192R1 = 22
ECC_BRAINPOOLP224R1 = 23
ECC_BRAINPOOLP256R1 = 24
ECC_BRAINPOOLP320R1 = 25
ECC_BRAINPOOLP384R1 = 26
ECC_BRAINPOOLP512R1 = 27

if _lib.RSA_ENABLED:
    MGF1NONE = _lib.WC_MGF1NONE
    MGF1SHA1 = _lib.WC_MGF1SHA1
    MGF1SHA224 = _lib.WC_MGF1SHA224
    MGF1SHA256 = _lib.WC_MGF1SHA256
    MGF1SHA384 = _lib.WC_MGF1SHA384
    MGF1SHA512 = _lib.WC_MGF1SHA512

    HASH_TYPE_NONE = _lib.WC_HASH_TYPE_NONE
    HASH_TYPE_MD2 = _lib.WC_HASH_TYPE_MD2
    HASH_TYPE_MD4 = _lib.WC_HASH_TYPE_MD4
    HASH_TYPE_MD5 = _lib.WC_HASH_TYPE_MD5
    HASH_TYPE_SHA = _lib.WC_HASH_TYPE_SHA
    HASH_TYPE_SHA224 = _lib.WC_HASH_TYPE_SHA224
    HASH_TYPE_SHA256 = _lib.WC_HASH_TYPE_SHA256
    HASH_TYPE_SHA384 = _lib.WC_HASH_TYPE_SHA384
    HASH_TYPE_SHA512 = _lib.WC_HASH_TYPE_SHA512
    HASH_TYPE_MD5_SHA = _lib.WC_HASH_TYPE_MD5_SHA
    HASH_TYPE_SHA3_224 = _lib.WC_HASH_TYPE_SHA3_224
    HASH_TYPE_SHA3_256 = _lib.WC_HASH_TYPE_SHA3_256
    HASH_TYPE_SHA3_384 = _lib.WC_HASH_TYPE_SHA3_384
    HASH_TYPE_SHA3_512 = _lib.WC_HASH_TYPE_SHA3_512
    HASH_TYPE_BLAKE2B = _lib.WC_HASH_TYPE_BLAKE2B
    HASH_TYPE_BLAKE2S = _lib.WC_HASH_TYPE_BLAKE2S


class _Cipher(ABC):
    """
    A **PEP 272: Block Encryption Algorithms** compliant
    **Symmetric Key Cipher**.
    """
    def __init__(self, key: BytesOrStr, mode: int, IV: BytesOrStr | None = None) -> None:
        if mode not in _FEEDBACK_MODES:
            raise ValueError("this mode is not supported")

        # Both supported modes (CBC, CTR) require an IV / initial counter.
        if IV is None:
            raise ValueError("this mode requires an 'IV' string")

        self.mode = mode

        key = t2b(key)
        if IV is not None:
            IV = t2b(IV)

        if self.key_size:
            if self.key_size != len(key):
                raise ValueError(f"key must be {self.key_size} in length, not {len(key)}")
        elif self._key_sizes:
            if len(key) not in self._key_sizes:
                raise ValueError(f"key must be {self._key_sizes} in length, not {len(key)}")
        elif not key:  # pragma: no cover
            raise ValueError("key must not be 0 in length")

        if IV is not None and len(IV) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} in length, not {len(IV)}")

        self._native_object = _ffi.new(self._native_type)
        self._enc = None
        self._dec = None
        self._key = key

        if IV:
            self._IV = IV
        else:  # pragma: no cover
            self._IV = bytes(self.block_size)

    @property
    @abstractmethod
    def _native_type(self) -> str: ...

    @property
    @abstractmethod
    def block_size(self) -> int: ...

    @property
    @abstractmethod
    def key_size(self) -> int: ...

    @property
    @abstractmethod
    def _key_sizes(self) -> list[int]: ...

    @abstractmethod
    def _set_key(self, direction: int) -> int: ...

    @abstractmethod
    def _encrypt(self, destination: _ffi.CData, source: bytes) -> int: ...

    @abstractmethod
    def _decrypt(self, destination: _ffi.CData, source: bytes) -> int: ...

    @classmethod
    def new(cls, key: BytesOrStr, mode: int, IV: BytesOrStr | None = None, **kwargs: int) -> _Cipher:  # pylint: disable=W0613
        """
        Returns a ciphering object, using the secret key contained in
        the string **key**, and using the feedback mode **mode**, which
        must be one of the supported MODE_* values (MODE_CBC, MODE_CTR).

        Both supported modes require **IV** to be provided as a string of
        the same length as the block size. Not providing a value of **IV**
        will result in a ValueError exception being raised.
        """
        return cls(key, mode, IV)

    def encrypt(self, string: BytesOrStr) -> bytes:
        """
        Encrypts a non-empty string, using the key-dependent data in
        the object, and with the appropriate feedback mode.

        In MODE_CBC the string's length must be an exact multiple of the
        algorithm's block size. MODE_CTR is a stream mode and imposes no
        length restriction.

        Returns a string containing the ciphertext.
        """
        string = t2b(string)
        if not string:
            raise ValueError(
                    "empty string not allowed")

        if len(string) % self.block_size and "ChaCha" not in self._native_type and self.mode != MODE_CTR:
            raise ValueError(f"string must be a multiple of {self.block_size} in length")

        if self._enc is None:
            self._enc = _ffi.new(self._native_type)
            ret = self._set_key(_ENCRYPTION)
            if ret < 0:  # pragma: no cover
                self._enc = None
                raise WolfCryptApiError("Invalid key error", ret)

        result = _ffi.new(f"byte[{len(string)}]")
        ret = self._encrypt(result, string)
        if ret < 0:  # pragma: no cover
            raise WolfCryptApiError("Encryption error", ret)

        return _ffi.buffer(result)[:]

    def decrypt(self, string: BytesOrStr) -> bytes:
        """
        Decrypts **string**, using the key-dependent data in the
        object and with the appropriate feedback mode.

        In MODE_CBC the string's length must be an exact multiple of the
        algorithm's block size. MODE_CTR is a stream mode and imposes no
        length restriction.

        Returns a string containing the plaintext.
        """
        string = t2b(string)

        if not string:
            raise ValueError("empty string not allowed")

        if len(string) % self.block_size and "ChaCha" not in self._native_type and self.mode != MODE_CTR:
            raise ValueError(f"string must be a multiple of {self.block_size} in length")

        if self._dec is None:
            self._dec = _ffi.new(self._native_type)
            ret = self._set_key(_DECRYPTION)
            if ret < 0:  # pragma: no cover
                self._dec = None
                raise WolfCryptApiError("Invalid key error", ret)

        result = _ffi.new(f"byte[{len(string)}]")
        ret = self._decrypt(result, string)
        if ret < 0:  # pragma: no cover
            raise WolfCryptApiError("Decryption error", ret)

        return _ffi.buffer(result)[:]


if _lib.AES_ENABLED:
    class Aes(_Cipher):
        """
        The **Advanced Encryption Standard** (AES), a.k.a. Rijndael, is
        a symmetric-key cipher standardized by **NIST**.
        """
        block_size = 16
        key_size = None  # 16, 24, 32
        _key_sizes = [16, 24, 32]
        _native_type = "Aes *"

        @override
        def _set_key(self, direction: int) -> int:
            if direction == _ENCRYPTION:
                assert self._enc is not None
                return _lib.wc_AesSetKey(
                    self._enc, self._key, len(self._key), self._IV, _ENCRYPTION)
            assert self._dec is not None
            if self.mode == MODE_CTR:
                return _lib.wc_AesSetKey(
                    self._dec, self._key, len(self._key), self._IV, _ENCRYPTION)
            return _lib.wc_AesSetKey(
                self._dec, self._key, len(self._key), self._IV, _DECRYPTION)

        @override
        def _encrypt(self, destination: _ffi.CData, source: bytes) -> int:
            assert self._enc is not None
            if self.mode == MODE_CBC:
                return _lib.wc_AesCbcEncrypt(self._enc, destination,
                        source, len(source))
            elif self.mode == MODE_CTR:
                return _lib.wc_AesCtrEncrypt(self._enc, destination,
                        source, len(source))
            else:
                raise ValueError("Invalid mode associated to cipher")

        @override
        def _decrypt(self, destination: _ffi.CData, source: bytes) -> int:
            assert self._dec is not None
            if self.mode == MODE_CBC:
                return _lib.wc_AesCbcDecrypt(self._dec, destination,
                        source, len(source))
            elif self.mode == MODE_CTR:
                return _lib.wc_AesCtrEncrypt(self._dec, destination,
                        source, len(source))
            else:
                raise ValueError("Invalid mode associated to cipher")

if _lib.AES_SIV_ENABLED:
    class AesSiv:
        """
        AES-SIV (Synthetic Initialization Vector) implementation as described in RFC 5297.
        """
        # RFC 5297 defines key sizes of 256-, 384-, or 512 bits.
        _key_sizes = [32, 48, 64]
        block_size = 16

        def __init__(self, key: BytesOrStr) -> None:
            self._key = t2b(key)
            if len(self._key) not in AesSiv._key_sizes:
                raise ValueError(f"key must be {AesSiv._key_sizes} in length, not {len(self._key)}")

        def encrypt(self, associated_data: BytesOrStr | Sequence[bytes] | Sequence[bytearray] | Sequence[str] | Sequence[memoryview], nonce: BytesOrStr, plaintext: BytesOrStr) -> tuple[bytes, bytes]:
            """
            Encrypt plaintext data using the nonce provided. The associated
            data is not encrypted but is included in the authentication tag.

            Associated data may be provided as a single str, bytes,
            bytearray, or memoryview, or as a list of any of those in case
            of multiple blocks.

            Returns a tuple of the IV and ciphertext.
            """
            # Prepare the associated data blocks. Make sure to hold on to the
            # returned references until the C function has been called in order
            # to prevent garbage collection of them until the function is done.
            prep_associated_data, _refs = (
                AesSiv._prepare_associated_data(associated_data))
            nonce = t2b(nonce)
            plaintext = t2b(plaintext)
            siv = _ffi.new(f"byte[{AesSiv.block_size}]")
            ciphertext = _ffi.new(f"byte[{len(plaintext)}]")
            ret = _lib.wc_AesSivEncrypt_ex(self._key, len(self._key),
                prep_associated_data, len(prep_associated_data), nonce, len(nonce),
                plaintext, len(plaintext), siv, ciphertext)
            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("AES-SIV encryption error", ret)
            return _ffi.buffer(siv)[:], _ffi.buffer(ciphertext)[:]

        def decrypt(self, associated_data: BytesOrStr | Sequence[bytes] | Sequence[bytearray] | Sequence[str] | Sequence[memoryview], nonce: BytesOrStr, siv: BytesOrStr, ciphertext: BytesOrStr) -> bytes:
            """
            Decrypt the ciphertext using the nonce and SIV provided.
            The integrity of the associated data is checked.

            Associated data may be provided as a single str, bytes,
            bytearray, or memoryview, or as a list of any of those in case
            of multiple blocks.

            Returns the decrypted plaintext.
            """
            # Prepare the associated data blocks. Make sure to hold on to the
            # returned references until the C function has been called in order
            # to prevent garbage collection of them until the function is done.
            prep_associated_data, _refs = (
                AesSiv._prepare_associated_data(associated_data))
            nonce = t2b(nonce)
            siv = t2b(siv)
            if len(siv) != AesSiv.block_size:
                raise ValueError(f"SIV must be {AesSiv.block_size} in length, not {len(siv)}")
            ciphertext = t2b(ciphertext)
            plaintext = _ffi.new(f"byte[{len(ciphertext)}]")
            ret = _lib.wc_AesSivDecrypt_ex(self._key, len(self._key),
                prep_associated_data, len(prep_associated_data), nonce, len(nonce),
                ciphertext, len(ciphertext), siv, plaintext)
            if ret < 0:
                raise WolfCryptApiError("AES-SIV decryption error", ret)
            return _ffi.buffer(plaintext)[:]

        @staticmethod
        def _prepare_associated_data(associated_data: BytesOrStr | Sequence[bytes] | Sequence[bytearray] | Sequence[str] | Sequence[memoryview]) -> tuple[_ffi.CData, bytes | list[bytes]]:
            """
            Prepare associated data for sending to C library.

            Associated data may be provided as a single str, bytes,
            bytearray, or memoryview, or as a list of any of those in case
            of multiple blocks.

            The result is a tuple of the list of cffi cdata pointers to
            AesSivAssoc structures, as well as the converted associated
            data blocks. The caller **must** hold on to these until the
            C function has been called, in order to make sure that the memory
            is not freed by the FFI garbage collector before the data is read.
            """
            if isinstance(associated_data, (str, bytes, bytearray, memoryview)):
                # A single block is provided.
                # Make sure we have bytes.
                associated_data_bytes = t2b(associated_data)
                result = _ffi.new("AesSivAssoc[1]")
                result[0].assoc = _ffi.from_buffer(associated_data_bytes)
                result[0].assocSz = len(associated_data_bytes)
            else:
                # It is assumed that a list is provided.
                num_blocks = len(associated_data)
                if num_blocks > 126:
                    raise WolfCryptError("AES-SIV does not support more than 126 blocks "
                                         f"of associated data, got: {num_blocks}")
                # Make sure we have bytes.
                associated_data_bytes = [t2b(block) for block in associated_data]
                result = _ffi.new("AesSivAssoc[]", num_blocks)
                for index, block in enumerate(associated_data_bytes):
                    result[index].assoc = _ffi.from_buffer(block)
                    result[index].assocSz = len(block)
            # Return the converted associated data blocks so the caller can
            # hold on to them until the function has been called.
            return result, associated_data_bytes


if _lib.AESGCM_STREAM_ENABLED:
    class AesGcmStream:
        """
        AES GCM Stream
        """
        block_size = 16
        _key_sizes = [16, 24, 32]
        _native_type = "Aes *"
        # making sure _lib.wc_AesFree outlives Aes instances
        _delete = staticmethod(_lib.wc_AesFree)

        def __init__(self, key: BytesOrStr, IV: BytesOrStr, tag_bytes: int = 16) -> None:
            """
            tag_bytes is the number of bytes to use for the authentication tag during encryption
            """
            key = t2b(key)
            IV = t2b(IV)
            # NIST SP 800-38D valid GCM tag lengths: 16, 15, 14, 13, 12, 8, 4 bytes.
            if tag_bytes not in (4, 8, 12, 13, 14, 15, 16):
                raise ValueError(
                    "tag_bytes must be one of 4, 8, 12, 13, 14, 15, or 16")
            if tag_bytes < _lib.MIN_AUTH_TAG_SZ:
                raise ValueError(
                    f"tag_bytes {tag_bytes} not supported by current build configuration, "
                    f"minimum: {_lib.MIN_AUTH_TAG_SZ}"
                )
            # Per-instance state: AAD, tag length, and current mode (enc/dec).
            self._aad = b""
            self._tag_bytes = tag_bytes
            self._mode = None
            if len(key) not in self._key_sizes:
                raise ValueError(f"key must be {self._key_sizes} in length, not {len(key)}")
            self._init_done = False
            self._native_object = _ffi.new(self._native_type)
            ret = _lib.wc_AesInit(self._native_object, _ffi.NULL, -2)
            if ret < 0:
                raise WolfCryptApiError("AES init error", ret)
            self._init_done = True
            ret = _lib.wc_AesGcmInit(self._native_object, key, len(key), IV, len(IV))
            if ret < 0:
                raise WolfCryptApiError("Init error", ret)

        def __del__(self) -> None:
            if getattr(self, '_init_done', False):
                self._delete(self._native_object)
                self._init_done = False

        def set_aad(self, data: BytesOrStr) -> None:
            """
            Set the additional authentication data for the stream
            """
            if self._mode is not None:
                raise WolfCryptError("AAD can only be set before encrypt() or decrypt() is called")
            self._aad = t2b(data)

        def get_aad(self) -> bytes:
            return self._aad

        def encrypt(self, data: BytesOrStr) -> bytes:
            """
            Add more data to the encryption stream
            """
            data = t2b(data)
            aad = b""
            if self._mode is None:
                self._mode = _ENCRYPTION
                aad = self._aad
            elif self._mode == _DECRYPTION:
                raise WolfCryptError("Class instance already in use for decryption")
            buf = _ffi.new(f"byte[{len(data)}]")
            ret = _lib.wc_AesGcmEncryptUpdate(self._native_object, buf, data, len(data), aad, len(aad))
            if ret < 0:
                raise WolfCryptApiError("Encryption error", ret)
            return bytes(buf)

        def decrypt(self, data: BytesOrStr) -> bytes:
            """
            Add more data to the decryption stream
            """
            aad = b""
            data = t2b(data)
            if self._mode is None:
                self._mode = _DECRYPTION
                aad = self._aad
            elif self._mode == _ENCRYPTION:
                raise WolfCryptError("Class instance already in use for encryption")
            buf = _ffi.new(f"byte[{len(data)}]")
            ret = _lib.wc_AesGcmDecryptUpdate(self._native_object, buf, data, len(data), aad, len(aad))
            if ret < 0:
                raise WolfCryptApiError("Decryption error", ret)
            return bytes(buf)

        def final(self, authTag: BytesOrStr | None = None) -> bytes | None:
            """
            When encrypting, finalize the stream and return an authentication tag for the stream.
            When decrypting, verify the authentication tag for the stream.
            The authTag parameter is only used for decrypting.
            """
            if self._mode is None:
                raise WolfCryptError("Final called with no encryption or decryption")
            elif self._mode == _ENCRYPTION:
                authTag_out = _ffi.new(f"byte[{self._tag_bytes}]")
                ret = _lib.wc_AesGcmEncryptFinal(self._native_object, authTag_out, self._tag_bytes)
                if ret < 0:
                    raise WolfCryptApiError("Encryption error", ret)
                return _ffi.buffer(authTag_out)[:]
            else:
                if authTag is None:
                    raise WolfCryptError("authTag parameter required")
                authTag = t2b(authTag)
                if len(authTag) != self._tag_bytes:
                    raise ValueError(f"authTag must be {self._tag_bytes} bytes, got {len(authTag)}")
                ret = _lib.wc_AesGcmDecryptFinal(
                    self._native_object, authTag, self._tag_bytes)
                if ret < 0:
                    raise WolfCryptApiError("Decryption error", ret)



if _lib.CHACHA_ENABLED:
    class ChaCha(_Cipher):
        """
        ChaCha20
        """
        block_size = 16
        key_size = None  # 16, 24, 32
        _key_sizes = [16, 32]
        _native_type = "ChaCha *"
        _IV_nonce = b""
        _IV_counter = 0

        def __init__(self, key: BytesOrStr = "", size: int = 32) -> None:  # pylint: disable=unused-argument
            # size is kept for backwards compatibility; key length is now
            # derived from the actual key and validated against _key_sizes.
            self._native_object = _ffi.new(self._native_type)
            self._enc = None
            self._dec = None
            self._key = None
            if len(key) > 0:
                self._key = t2b(key)
                if len(self._key) not in self._key_sizes:
                    raise ValueError(f"key must be {self._key_sizes} in length, not {len(self._key)}")
                self.key_size = len(self._key)
            self._IV_nonce = b""
            self._IV_counter = 0
            # ChaCha takes no IV at construction; set_iv() must be called
            # before any encrypt()/decrypt() so a real nonce is available.
            self._iv_set = False

        @override
        def encrypt(self, string: BytesOrStr) -> bytes:
            self._require_iv()
            return super().encrypt(string)

        @override
        def decrypt(self, string: BytesOrStr) -> bytes:
            self._require_iv()
            return super().decrypt(string)

        def _require_iv(self) -> None:
            if not self._iv_set:
                raise WolfCryptError(
                    "set_iv() must be called before encrypt()/decrypt()")

        # Sentinel for "rekey both contexts" used by set_iv. Must not
        # collide with _ENCRYPTION (0) or _DECRYPTION (1).
        _REKEY_BOTH = -1

        @override
        def _set_key(self, direction: int) -> int:
            if self._key is None:
                return -1
            # _REKEY_BOTH re-keys whichever contexts are already allocated,
            # since changing the IV must reset both encrypt and decrypt
            # streams. _ENCRYPTION / _DECRYPTION only touch the matching
            # context so that lazy allocation from encrypt()/decrypt() does
            # not wipe the other direction's stream state.
            do_enc = self._enc and direction in (self._REKEY_BOTH, _ENCRYPTION)
            do_dec = self._dec and direction in (self._REKEY_BOTH, _DECRYPTION)
            if do_enc:
                assert self._enc is not None
                ret = _lib.wc_Chacha_SetKey(self._enc, self._key, len(self._key))
                if ret == 0:
                    ret = _lib.wc_Chacha_SetIV(self._enc, self._IV_nonce, self._IV_counter)
                if ret != 0:
                    return ret
            if do_dec:
                assert self._dec is not None
                ret = _lib.wc_Chacha_SetKey(self._dec, self._key, len(self._key))
                if ret == 0:
                    ret = _lib.wc_Chacha_SetIV(self._dec, self._IV_nonce, self._IV_counter)
                if ret != 0:
                    return ret
            return 0

        @override
        def _encrypt(self, destination: _ffi.CData, source: bytes) -> int:
            assert self._enc is not None
            return _lib.wc_Chacha_Process(self._enc, destination,
                                         source, len(source))
        @override
        def _decrypt(self, destination: _ffi.CData, source: bytes) -> int:
            assert self._dec is not None
            return _lib.wc_Chacha_Process(self._dec,
                                          destination, source, len(source))

        _NONCE_SIZE = 12

        def set_iv(self, nonce: BytesOrStr, counter: int = 0) -> None:
            self._IV_nonce = t2b(nonce)
            if len(self._IV_nonce) != self._NONCE_SIZE:
                raise ValueError(f"nonce must be {self._NONCE_SIZE} bytes, got {len(self._IV_nonce)}")
            self._IV_counter = counter
            self._iv_set = False
            ret = self._set_key(self._REKEY_BOTH)
            if ret < 0:
                raise WolfCryptApiError("ChaCha set_iv error", ret)
            self._iv_set = True

if _lib.CHACHA20_POLY1305_ENABLED:
    class ChaCha20Poly1305:
        """
        ChaCha20-Poly1305 AEAD cipher.

        One-shot encrypt/decrypt interface (non-streaming).
        """
        _key_sizes = [32]
        _tag_bytes = 16

        def __init__(self, key: BytesOrStr) -> None:
            self._key = t2b(key)
            if len(self._key) not in self._key_sizes:
                raise ValueError(f"key must be {self._key_sizes} in length, not {len(self._key)}")

        def encrypt(self, aad: BytesOrStr, iv: BytesOrStr, plaintext: BytesOrStr) -> tuple[bytes, bytes]:
            """
            Encrypt plaintext data using the IV/nonce provided. The
            associated data (aad) is not encrypted but is included in the
            authentication tag.

            Returns a tuple of (ciphertext, authTag).
            """
            aad = t2b(aad)
            iv = t2b(iv)
            if len(iv) != 12:
                raise ValueError(f"iv must be 12 bytes, got {len(iv)}")
            plaintext = t2b(plaintext)
            ciphertext = _ffi.new(f"byte[{len(plaintext)}]")
            authTag = _ffi.new(f"byte[{self._tag_bytes}]")
            ret = _lib.wc_ChaCha20Poly1305_Encrypt(
                self._key,
                iv,
                aad,
                len(aad),
                plaintext,
                len(plaintext),
                ciphertext,
                authTag
            )
            if ret < 0:
                raise WolfCryptApiError("Encryption error", ret)
            return bytes(ciphertext), bytes(authTag)

        def decrypt(self, aad: BytesOrStr, iv: BytesOrStr, authTag: BytesOrStr, ciphertext: BytesOrStr) -> bytes:
            """
            Decrypt the ciphertext using the IV/nonce and authentication tag
            provided. The integrity of the associated data (aad) is checked.

            Returns the decrypted plaintext.
            """
            aad = t2b(aad)
            iv = t2b(iv)
            if len(iv) != 12:
                raise ValueError(f"iv must be 12 bytes, got {len(iv)}")
            authTag = t2b(authTag)
            if len(authTag) != self._tag_bytes:
                raise ValueError(f"authTag must be {self._tag_bytes} bytes, got {len(authTag)}")
            ciphertext = t2b(ciphertext)
            plaintext = _ffi.new(f"byte[{len(ciphertext)}]")
            ret = _lib.wc_ChaCha20Poly1305_Decrypt(
                self._key,
                iv,
                aad,
                len(aad),
                ciphertext,
                len(ciphertext),
                authTag,
                plaintext
            )
            if ret < 0:
                raise WolfCryptApiError("Decryption error", ret)
            return bytes(plaintext)

if _lib.DES3_ENABLED:
    class Des3(_Cipher):
        """
        **Triple DES** (3DES) is the common name for the **Triple Data
        Encryption Algorithm** (TDEA or Triple DEA) symmetric-key block
        cipher, which applies the **Data Encryption Standard** (DES)
        cipher algorithm three times to each data block.
        """
        block_size = 8
        key_size = 24
        _key_sizes = [24]
        _native_type = "Des3 *"

        def __init__(self, key: BytesOrStr, mode: int, IV: BytesOrStr | None = None) -> None:
            # Intentionally stricter than _Cipher.__init__, which accepts both
            # CBC and CTR. wolfCrypt has no 3DES-CTR implementation, so reject
            # MODE_CTR here with a clearer error before delegating.
            if mode != MODE_CBC:
                raise ValueError("Des3 only supports MODE_CBC")
            super().__init__(key, mode, IV)

        @override
        def _set_key(self, direction: int) -> int:
            if direction == _ENCRYPTION:
                assert self._enc is not None
                return _lib.wc_Des3_SetKey(self._enc, self._key, self._IV, _ENCRYPTION)

            assert self._dec is not None
            return _lib.wc_Des3_SetKey(self._dec, self._key, self._IV, _DECRYPTION)

        @override
        def _encrypt(self, destination: _ffi.CData, source: bytes) -> int:
            assert self._enc is not None
            return _lib.wc_Des3_CbcEncrypt(self._enc, destination, source, len(source))

        @override
        def _decrypt(self, destination: _ffi.CData, source: bytes) -> int:
            assert self._dec is not None
            return _lib.wc_Des3_CbcDecrypt(self._dec, destination, source, len(source))


if _lib.RSA_ENABLED:
    class _Rsa:  # pylint: disable=too-few-public-methods
        RSA_MIN_PAD_SIZE = 11
        _mgf: int | None = None
        _hash_type = None

        def __init__(self, rng: Random | None = None) -> None:
            if rng is None:
                rng = Random()

            self.native_object = _ffi.new("RsaKey *")
            ret = _lib.wc_InitRsaKey(self.native_object, _ffi.NULL)
            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("Invalid key error", ret)

            self._random = rng
            if _lib.RSA_BLINDING_ENABLED:
                ret = _lib.wc_RsaSetRNG(self.native_object,
                        self._random.native_object)
                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("Key initialization error", ret)

        # making sure _lib.wc_FreeRsaKey outlives RsaKey instances
        _delete = staticmethod(_lib.wc_FreeRsaKey)

        def __del__(self) -> None:
            if self.native_object:
                self._delete(self.native_object)

        def set_mgf(self, mgf: int) -> None:
            self._mgf = mgf

        def _get_mgf(self) -> None:
            if self._hash_type == _lib.WC_HASH_TYPE_SHA:
                self._mgf = _lib.WC_MGF1SHA1
            elif self._hash_type == _lib.WC_HASH_TYPE_SHA224:
                self._mgf = _lib.WC_MGF1SHA224
            elif self._hash_type == _lib.WC_HASH_TYPE_SHA256:
                self._mgf = _lib.WC_MGF1SHA256
            elif self._hash_type == _lib.WC_HASH_TYPE_SHA384:
                self._mgf = _lib.WC_MGF1SHA384
            elif self._hash_type == _lib.WC_HASH_TYPE_SHA512:
                self._mgf = _lib.WC_MGF1SHA512
            else:
                self._mgf = _lib.WC_MGF1NONE



    class RsaPublic(_Rsa, SupportsRsaVerify):
        def __init__(self, key: BytesOrStr, hash_type: int | None = None, rng: Random | None = None) -> None:
            super().__init__(rng)

            key = t2b(key)
            self._hash_type = hash_type

            idx = _ffi.new("word32*")
            idx[0] = 0

            ret = _lib.wc_RsaPublicKeyDecode(key, idx, self.native_object, len(key))
            if ret < 0:
                raise WolfCryptApiError("Invalid key error", ret)

            self.output_size = _lib.wc_RsaEncryptSize(self.native_object)
            self.size = len(key)
            if self.output_size <= 0:  # pragma: no cover
                raise WolfCryptApiError("Invalid key error", self.output_size)

        if _lib.ASN_ENABLED:
            @classmethod
            def from_pem(cls, file: bytes, hash_type: int | None = None, rng: Random | None = None) -> RsaPublic:
                der = pem_to_der(file, _lib.PUBLICKEY_TYPE)
                return cls(key=der, hash_type=hash_type, rng=rng)

        def encrypt(self, plaintext: BytesOrStr) -> bytes:
            """
            Encrypts **plaintext**, using the public key data in the
            object. The plaintext's length must not be greater than:

                **self.output_size - self.RSA_MIN_PAD_SIZE**

            Returns a string containing the ciphertext.
            """

            plaintext = t2b(plaintext)
            ciphertext = _ffi.new(f"byte[{self.output_size}]")

            ret = _lib.wc_RsaPublicEncrypt(plaintext, len(plaintext),
                                           ciphertext, self.output_size,
                                           self.native_object,
                                           self._random.native_object)

            if ret != self.output_size:  # pragma: no cover
                raise WolfCryptApiError("Encryption error", ret)

            return _ffi.buffer(ciphertext)[:]

        def encrypt_oaep(self, plaintext: BytesOrStr, label: BytesOrStr = "") -> bytes:
            if not self._hash_type:
                raise WolfCryptError("Hash type not set. Cannot use OAEP padding without a hash type.")
            plaintext = t2b(plaintext)
            label = t2b(label)
            ciphertext = _ffi.new(f"byte[{self.output_size}]")
            if self._mgf is None:
                self._get_mgf()
                assert self._mgf is not None
            ret = _lib.wc_RsaPublicEncrypt_ex(plaintext, len(plaintext),
                                              ciphertext, self.output_size,
                                              self.native_object,
                                              self._random.native_object,
                                              _lib.WC_RSA_OAEP_PAD, self._hash_type,
                                              self._mgf, label, len(label))

            if ret != self.output_size:  # pragma: no cover
                raise WolfCryptApiError("Encryption error", ret)

            return _ffi.buffer(ciphertext)[:]

        @override
        def verify(self, signature: BytesOrStr) -> bytes:
            """
            Verifies **signature**, using the public key data in the
            object. The signature's length must be equal to:

                **self.output_size**

            Returns a string containing the plaintext.
            """
            signature = t2b(signature)
            plaintext = _ffi.new(f"byte[{self.output_size}]")

            ret = _lib.wc_RsaSSL_Verify(signature, len(signature),
                                        plaintext, self.output_size,
                                        self.native_object)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("Verify error", ret)

            return _ffi.buffer(plaintext, ret)[:]

        if _lib.RSA_PSS_ENABLED:
            def verify_pss(self, plaintext: BytesOrStr, signature: BytesOrStr) -> bool:
                """
                Verifies **signature**, using the public key data in the
                object. The signature's length must be equal to:

                    **self.output_size**

                Returns a string containing the plaintext.
                """
                if not self._hash_type:
                    raise WolfCryptError("Hash type not set. Cannot verify a PSS signature without a hash type.")

                hash_cls = hash_type_to_cls(self._hash_type)
                if not hash_cls:
                    raise WolfCryptError("Unsupported PSS hash type.")

                plaintext = t2b(plaintext)
                signature = t2b(signature)
                if self._mgf is None:
                    self._get_mgf()
                    assert self._mgf is not None
                verify = _ffi.new(f"byte[{self.output_size}]")

                ret = _lib.wc_RsaPSS_Verify(signature, len(signature),
                                            verify, self.output_size,
                                            self._hash_type, self._mgf,
                                            self.native_object)

                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("Verify error", ret)

                digest = hash_cls.new(plaintext).digest()
                ret = _lib.wc_RsaPSS_CheckPadding(digest, len(digest),
                                                  verify, ret, self._hash_type)

                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("PSS padding check error", ret)

                return ret == 0


    class RsaPrivate(RsaPublic, SupportsRsaSign):
        if _lib.KEYGEN_ENABLED:
            @classmethod
            def make_key(cls, size: int, rng: Random | None = None, hash_type: int | None = None) -> RsaPrivate:
                """
                Generates a new key pair of desired length **size**.
                """
                if rng is None:
                    rng = Random()
                rsa = cls(hash_type=hash_type, rng=rng)

                ret = _lib.wc_MakeRsaKey(rsa.native_object, size, 65537,
                        rng.native_object)
                if ret < 0:
                    raise WolfCryptApiError("Key generation error", ret)

                rsa.output_size = _lib.wc_RsaEncryptSize(rsa.native_object)
                rsa.size = size
                if rsa.output_size < 0:  # pragma: no cover
                    raise WolfCryptApiError("Invalid key size error", rsa.output_size)

                return rsa

        def __init__(self, key: BytesOrStr | None = None, hash_type: int | None = None, rng: Random | None = None) -> None:  # pylint: disable=super-init-not-called

            _Rsa.__init__(self, rng)  # pylint: disable=non-parent-init-called
            self._hash_type = hash_type
            idx = _ffi.new("word32*")
            idx[0] = 0

            if key is not None:
                key = t2b(key)
                ret = _lib.wc_RsaPrivateKeyDecode(key, idx,
                                              self.native_object, len(key))
                if ret < 0:
                    idx[0] = 0
                    # wc_GetPkcs8TraditionalOffset takes byte* (non-const) per
                    # the wolfSSL public header, so route it through a CFFI-
                    # owned buffer rather than handing it a writable pointer
                    # into the Python bytes object.
                    key_buf = _ffi.new("byte[]", key)
                    ret = _lib.wc_GetPkcs8TraditionalOffset(key_buf, idx, len(key))
                    if ret < 0:
                        raise WolfCryptApiError("Invalid key error", ret)

                    ret = _lib.wc_RsaPrivateKeyDecode(key, idx,
                                              self.native_object, len(key))
                    if ret < 0:
                        raise WolfCryptApiError("Invalid key error", ret)

                self.size = len(key)
                self.output_size = _lib.wc_RsaEncryptSize(self.native_object)
                if self.output_size <= 0:  # pragma: no cover
                    raise WolfCryptApiError("Invalid key size error", self.output_size)

        if _lib.ASN_ENABLED:
            @override
            @classmethod
            def from_pem(cls, file: bytes, hash_type: int | None = None, rng: Random | None = None) -> RsaPrivate:
                der = pem_to_der(file, _lib.PRIVATEKEY_TYPE)
                return cls(key=der, hash_type=hash_type, rng=rng)

        if _lib.KEYGEN_ENABLED:
            def encode_key(self) -> tuple[bytes, bytes]:
                """
                Encodes the RSA private and public keys in an ASN sequence.

                Returns the encoded key.
                """
                priv = _ffi.new(f"byte[{self.size * 4}]")
                pub = _ffi.new(f"byte[{self.size * 4}]")


                ret = _lib.wc_RsaKeyToDer(self.native_object, priv, self.size)
                if ret <= 0:  # pragma: no cover
                    raise WolfCryptApiError("Private RSA key error", ret)
                privlen = ret
                ret = _lib.wc_RsaKeyToPublicDer(self.native_object, pub,
                        self.size)
                if ret <= 0:  # pragma: no cover
                    raise WolfCryptApiError("Public RSA key encode error", ret)
                publen = ret
                return _ffi.buffer(priv, privlen)[:], _ffi.buffer(pub,
                        publen)[:]

        def decrypt(self, ciphertext: BytesOrStr) -> bytes:
            """
            Decrypts **ciphertext**, using the private key data in the
            object. The ciphertext's length must be equal to:

                **self.output_size**

            Returns a string containing the plaintext.
            """
            ciphertext = t2b(ciphertext)
            plaintext = _ffi.new(f"byte[{self.output_size}]")

            ret = _lib.wc_RsaPrivateDecrypt(ciphertext, len(ciphertext),
                                            plaintext, self.output_size,
                                            self.native_object)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("Decryption error", ret)

            return _ffi.buffer(plaintext, ret)[:]

        def decrypt_oaep(self, ciphertext: BytesOrStr, label: BytesOrStr = "") -> bytes:
            """
            Decrypts **ciphertext**, using the private key data in the
            object. The ciphertext's length must be equal to:

                **self.output_size**

            Returns a string containing the plaintext.
            """
            if not self._hash_type:
                raise WolfCryptError("Hash type not set. Cannot use OAEP padding without a hash type.")
            ciphertext = t2b(ciphertext)
            label = t2b(label)
            plaintext = _ffi.new(f"byte[{self.output_size}]")
            if self._mgf is None:
                self._get_mgf()
                assert self._mgf is not None
            ret = _lib.wc_RsaPrivateDecrypt_ex(ciphertext, len(ciphertext),
                                               plaintext, self.output_size,
                                               self.native_object,
                                               _lib.WC_RSA_OAEP_PAD, self._hash_type,
                                               self._mgf, label, len(label))

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("Decryption error", ret)

            return _ffi.buffer(plaintext, ret)[:]

        @override
        def sign(self, plaintext: BytesOrStr) -> bytes:
            """
            Signs **plaintext**, using the private key data in the object.
            The plaintext's length must not be greater than:

                **self.output_size - self.RSA_MIN_PAD_SIZE**

            Returns a string containing the signature.
            """
            plaintext = t2b(plaintext)
            signature = _ffi.new(f"byte[{self.output_size}]")

            ret = _lib.wc_RsaSSL_Sign(plaintext, len(plaintext),
                                      signature, self.output_size,
                                      self.native_object,
                                      self._random.native_object)

            if ret != self.output_size:  # pragma: no cover
                raise WolfCryptApiError("Signature error", ret)

            return _ffi.buffer(signature, self.output_size)[:]

        if _lib.RSA_PSS_ENABLED:
            def sign_pss(self, plaintext: BytesOrStr) -> bytes:
                """
                Signs **plaintext**, using the private key data in the object.
                The plaintext's length must not be greater than:

                    **self.output_size - self.RSA_MIN_PAD_SIZE**

                Returns a string containing the signature.
                """
                if not self._hash_type:
                    raise WolfCryptError("Hash type not set. Cannot verify a PSS signature without a hash type.")

                hash_cls = hash_type_to_cls(self._hash_type)
                if not hash_cls:
                    raise WolfCryptError("Unsupported PSS hash type.")

                plaintext = t2b(plaintext)
                digest = hash_cls.new(plaintext).digest()

                signature = _ffi.new(f"byte[{self.output_size}]")
                if self._mgf is None:
                    self._get_mgf()
                    assert self._mgf is not None

                ret = _lib.wc_RsaPSS_Sign(digest, len(digest),
                                          signature, self.output_size,
                                          self._hash_type, self._mgf,
                                          self.native_object,
                                          self._random.native_object)

                if ret != self.output_size:  # pragma: no cover
                    raise WolfCryptApiError("Signature error", ret)

                return _ffi.buffer(signature, self.output_size)[:]


if _lib.ECC_ENABLED:
    class _Ecc:  # pylint: disable=too-few-public-methods
        def __init__(self) -> None:
            self.native_object = _ffi.new("ecc_key *")
            ret = _lib.wc_ecc_init(self.native_object)
            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("Invalid key error", ret)

        # making sure _lib.wc_ecc_free outlives ecc_key instances
        _delete = staticmethod(_lib.wc_ecc_free)

        def __del__(self) -> None:
            if self.native_object:
                self._delete(self.native_object)

        @property
        def size(self) -> int:
            return _lib.wc_ecc_size(self.native_object)

        @property
        def max_signature_size(self) -> int:
            return _lib.wc_ecc_sig_size(self.native_object)


    class EccPublic(_Ecc):
        def __init__(self, key: BytesOrStr | None = None) -> None:
            _Ecc.__init__(self)

            if key:
                self.decode_key(key)

        def decode_key(self, key: BytesOrStr) -> None:
            """
            Decodes an ECC public key from an ASN sequence.
            """
            key = t2b(key)

            idx = _ffi.new("word32*")
            idx[0] = 0

            ret = _lib.wc_EccPublicKeyDecode(key, idx,
                                             self.native_object, len(key))
            if ret < 0:
                raise WolfCryptApiError("Key decode error", ret)
            if self.size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.size})")
            if self.max_signature_size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.max_signature_size})")

        def decode_key_raw(self, qx: BytesOrStr, qy: BytesOrStr, curve_id: int = ECC_SECP256R1) -> None:
            """
            Decodes an ECC public key from its raw elements: (Qx,Qy)
            """
            qx = t2b(qx)
            qy = t2b(qy)
            curve_size = _lib.wc_ecc_get_curve_size_from_id(curve_id)
            if curve_size <= 0:
                raise ValueError(f"Unknown ECC curve_id {curve_id}")
            if len(qx) != curve_size or len(qy) != curve_size:
                raise ValueError(
                    f"qx and qy must each be {curve_size} bytes for curve_id {curve_id}, got "
                    f"qx={len(qx)} qy={len(qy)}")
            ret = _lib.wc_ecc_import_unsigned(self.native_object, qx, qy,
                    _ffi.NULL, curve_id)
            if ret != 0:
                raise WolfCryptApiError("Key decode error", ret)

        def encode_key(self, with_curve: bool = True) -> bytes:
            """
            Encodes the ECC public key in an ASN sequence.

            Returns the encoded key.
            """
            key = _ffi.new(f"byte[{self.size * 4}]")

            ret = _lib.wc_EccPublicKeyToDer(self.native_object, key, len(key),
                                            with_curve)
            if ret <= 0:  # pragma: no cover
                raise WolfCryptApiError("Key encode error", ret)

            return _ffi.buffer(key, ret)[:]

        def encode_key_raw(self) -> tuple[bytes, bytes]:
            """
            Encodes the ECC public key in its two raw elements

            Returns (Qx, Qy)
            """
            Qx = _ffi.new(f"byte[{self.size}]")
            Qy = _ffi.new(f"byte[{self.size}]")
            qx_size = _ffi.new("word32[1]")
            qy_size = _ffi.new("word32[1]")
            qx_size[0] = self.size
            qy_size[0] = self.size

            ret = _lib.wc_ecc_export_public_raw(self.native_object, Qx,
                    qx_size, Qy, qy_size)
            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Key encode error", ret)

            return _ffi.buffer(Qx, qx_size[0])[:], _ffi.buffer(Qy,
                    qy_size[0])[:]

        def import_x963(self, x963: bytes) -> None:
            """
            Imports an ECC public key in ANSI X9.63 format.
            """
            ret = _lib.wc_ecc_import_x963(x963, len(x963), self.native_object)
            if ret != 0:
                raise WolfCryptApiError("x963 import error", ret)

        def export_x963(self) -> bytes:
            """
            Exports the public key data of the object in ANSI X9.63 format.

            Returns the exported key.
            """
            x963 = _ffi.new(f"byte[{self.size * 4}]")
            x963_size = _ffi.new("word32[1]")
            x963_size[0] = self.size * 4

            ret = _lib.wc_ecc_export_x963(self.native_object, x963, x963_size)
            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("x963 export error", ret)

            return _ffi.buffer(x963, x963_size[0])[:]

        def verify(self, signature: bytes, data: BytesOrStr) -> bool:
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
                raise WolfCryptApiError("Verify error", ret)

            return status[0] == 1

        if _lib.MPAPI_ENABLED:
            def verify_raw(self, R: bytes, S: bytes, data: BytesOrStr) -> bool:
                """
                Verifies signature from its raw elements **R** and **S**, using
                the public key data in the object.

                Returns **True** in case of a valid signature, otherwise
                **False**.
                """
                data = t2b(data)
                status = _ffi.new("int[1]")
                mpR = _ffi.new("mp_int[1]")
                mpS = _ffi.new("mp_int[1]")
                ret = _lib.mp_init(mpR)
                if ret != 0:  # pragma: no cover
                    raise WolfCryptApiError("wolfCrypt error", ret)
                ret = _lib.mp_init(mpS)
                if ret != 0:  # pragma: no cover
                    _lib.mp_clear(mpR)
                    raise WolfCryptApiError("wolfCrypt error", ret)

                try:
                    ret = _lib.mp_read_unsigned_bin(mpR, R, len(R))
                    if ret != 0:  # pragma: no cover
                        raise WolfCryptApiError("wolfCrypt error", ret)

                    ret = _lib.mp_read_unsigned_bin(mpS, S, len(S))
                    if ret != 0:  # pragma: no cover
                        raise WolfCryptApiError("wolfCrypt error", ret)

                    ret = _lib.wc_ecc_verify_hash_ex(mpR, mpS,
                                                  data, len(data),
                                                  status, self.native_object)

                    if ret < 0:
                        raise WolfCryptApiError("Verify error", ret)

                    return status[0] == 1
                finally:
                    _lib.mp_clear(mpR)
                    _lib.mp_clear(mpS)


    class EccPrivate(EccPublic):

        def __init__(self, key: BytesOrStr | None = None, rng: Random | None = None) -> None:
            super().__init__(key)
            self._rng = rng

        @classmethod
        def make_key(cls, size: int, rng: Random | None = None) -> EccPrivate:
            """
            Generates a new key pair of desired length **size**.
            """
            if rng is None:
                rng = Random()
            ecc = cls(rng=rng)
            assert ecc._rng is not None

            ret = _lib.wc_ecc_make_key(ecc._rng.native_object, size,
                    ecc.native_object)
            if ret < 0:
                raise WolfCryptApiError("Key generation error", ret)

            if _lib.ECC_TIMING_RESISTANCE_ENABLED and (not _lib.FIPS_ENABLED or
               _lib.FIPS_VERSION > 2):
                ret = _lib.wc_ecc_set_rng(ecc.native_object, ecc._rng.native_object)
                if ret < 0:
                    raise WolfCryptApiError("Error setting ECC RNG", ret)

            return ecc

        @override
        def decode_key(self, key: BytesOrStr) -> None:
            """
            Decodes an ECC private key from an ASN sequence.
            """
            key = t2b(key)

            idx = _ffi.new("word32*")
            idx[0] = 0

            ret = _lib.wc_EccPrivateKeyDecode(key, idx,
                                              self.native_object, len(key))
            if ret < 0:
                raise WolfCryptApiError("Key decode error", ret)
            if self.size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error {self.size}")
            if self.max_signature_size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.max_signature_size})")

        @override
        def decode_key_raw(self, qx: BytesOrStr, qy: BytesOrStr, d: BytesOrStr, curve_id: int = ECC_SECP256R1) -> None:
            """
            Decodes an ECC private key from its raw elements: public (Qx,Qy)
            and private(d)
            """
            qx = t2b(qx)
            qy = t2b(qy)
            d = t2b(d)
            curve_size = _lib.wc_ecc_get_curve_size_from_id(curve_id)
            if curve_size <= 0:
                raise ValueError(f"Unknown ECC curve_id {curve_id}")
            if (len(qx) != curve_size or len(qy) != curve_size
                    or len(d) != curve_size):
                raise ValueError(
                    f"qx, qy and d must each be {curve_size} bytes for curve_id {curve_id}, got "
                    f"qx={len(qx)} qy={len(qy)} d={len(d)}")
            ret = _lib.wc_ecc_import_unsigned(self.native_object, qx, qy, d,
                    curve_id)
            if ret != 0:
                raise WolfCryptApiError("Key decode error", ret)

        @override
        def encode_key(self) -> bytes:
            """
            Encodes the ECC private key in an ASN sequence.

            Returns the encoded key.
            """
            key = _ffi.new(f"byte[{self.size * 4}]")

            ret = _lib.wc_EccKeyToDer(self.native_object, key, len(key))
            if ret <= 0:  # pragma: no cover
                raise WolfCryptApiError("Key encode error", ret)

            return _ffi.buffer(key, ret)[:]

        @override
        def encode_key_raw(self) -> tuple[bytes, bytes, bytes]:
            """
            Encodes the ECC private key in its three raw elements

            Returns (Qx, Qy, d)
            """
            Qx = _ffi.new(f"byte[{self.size}]")
            Qy = _ffi.new(f"byte[{self.size}]")
            d = _ffi.new(f"byte[{self.size}]")
            qx_size = _ffi.new("word32[1]")
            qy_size = _ffi.new("word32[1]")
            d_size = _ffi.new("word32[1]")
            qx_size[0] = self.size
            qy_size[0] = self.size
            d_size[0] = self.size

            ret = _lib.wc_ecc_export_private_raw(self.native_object, Qx,
                    qx_size, Qy, qy_size, d, d_size)
            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Key encode error", ret)

            return _ffi.buffer(Qx, qx_size[0])[:], _ffi.buffer(Qy,
                    qy_size[0])[:], _ffi.buffer(d, d_size[0])[:]

        def shared_secret(self, peer: EccPublic) -> bytes:
            """
            Generates a new secret key using the private key data in the object
            and the peer's public key.

            Returns the shared secret.
            """
            shared_secret = _ffi.new(f"byte[{self.max_signature_size}]")
            secret_size = _ffi.new("word32[1]")
            secret_size[0] = self.max_signature_size

            ret = _lib.wc_ecc_shared_secret(self.native_object,
                                            peer.native_object,
                                            shared_secret, secret_size)

            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Shared secret error", ret)

            return _ffi.buffer(shared_secret, secret_size[0])[:]

        def sign(self, plaintext: BytesOrStr, rng: Random | None = None) -> bytes:
            """
            Signs **plaintext**, using the private key data in the object.

            Returns the signature.
            """
            if rng is None:
                rng = Random()
            plaintext = t2b(plaintext)
            signature = _ffi.new(f"byte[{self.max_signature_size}]")

            signature_size = _ffi.new("word32[1]")
            signature_size[0] = self.max_signature_size

            ret = _lib.wc_ecc_sign_hash(plaintext, len(plaintext),
                                        signature, signature_size,
                                        rng.native_object,
                                        self.native_object)

            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Signature error", ret)

            return _ffi.buffer(signature, signature_size[0])[:]

        if _lib.MPAPI_ENABLED:
            def sign_raw(self, plaintext: BytesOrStr, rng: Random | None = None) -> tuple[bytes, bytes]:
                """
                Signs **plaintext**, using the private key data in the object.

                Returns the signature in its two raw components r, s
                """
                if rng is None:
                    rng = Random()
                plaintext = t2b(plaintext)
                R = _ffi.new("mp_int[1]")
                S = _ffi.new("mp_int[1]")

                R_bin = _ffi.new(f"unsigned char[{self.size}]")
                S_bin = _ffi.new(f"unsigned char[{self.size}]")

                ret = _lib.mp_init(R)
                if ret != 0:  # pragma: no cover
                    raise WolfCryptApiError("wolfCrypt error", ret)
                ret = _lib.mp_init(S)
                if ret != 0:  # pragma: no cover
                    _lib.mp_clear(R)
                    raise WolfCryptApiError("wolfCrypt error", ret)

                try:
                    ret = _lib.wc_ecc_sign_hash_ex(plaintext, len(plaintext),
                                                rng.native_object,
                                                self.native_object,
                                                R, S)
                    if ret != 0:  # pragma: no cover
                        raise WolfCryptApiError("Signature error", ret)

                    ret = _lib.mp_to_unsigned_bin_len(R, R_bin, self.size)
                    if ret != 0:  # pragma: no cover
                        raise WolfCryptApiError("wolfCrypt error", ret)

                    ret = _lib.mp_to_unsigned_bin_len(S, S_bin, self.size)
                    if ret != 0:  # pragma: no cover
                        raise WolfCryptApiError("wolfCrypt error", ret)

                    return _ffi.buffer(R_bin, self.size)[:], _ffi.buffer(S_bin,
                            self.size)[:]
                finally:
                    _lib.mp_clear(R)
                    _lib.mp_clear(S)


if _lib.ED25519_ENABLED:
    class _Ed25519:  # pylint: disable=too-few-public-methods
        def __init__(self) -> None:
            self.native_object = _ffi.new("ed25519_key *")
            ret = _lib.wc_ed25519_init(self.native_object)
            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("Invalid key error", ret)

        # making sure _lib.wc_ed25519_free outlives ed25519_key instances
        _delete = staticmethod(_lib.wc_ed25519_free)

        def __del__(self) -> None:
            if self.native_object:
                self._delete(self.native_object)

        @property
        def size(self) -> int:
            return _lib.wc_ed25519_size(self.native_object)

        @property
        def max_signature_size(self) -> int:
            return _lib.wc_ed25519_sig_size(self.native_object)


    class Ed25519Public(_Ed25519):
        def __init__(self, key: BytesOrStr | None = None) -> None:
            _Ed25519.__init__(self)

            if key:
                self.decode_key(key)

        def decode_key(self, key: BytesOrStr) -> None:
            """
            Decodes an ED25519 public key
            """
            key = t2b(key)
            if len(key) < _lib.wc_ed25519_pub_size(self.native_object):
                raise WolfCryptError("Key decode error: key too short")

            idx = _ffi.new("word32*")
            idx[0] = 0
            ret = _lib.wc_ed25519_import_public(key, len(key),
                    self.native_object)
            if ret < 0:
                raise WolfCryptApiError("Key decode error", ret)
            if self.size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.size})")
            if self.max_signature_size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.max_signature_size})")

        def encode_key(self) -> bytes:
            """
            Encodes the ED25519 public key

            Returns the encoded key.
            """
            key = _ffi.new(f"byte[{self.size * 4}]")
            size = _ffi.new("word32[1]")

            size[0] = _lib.wc_ed25519_pub_size(self.native_object)

            ret = _lib.wc_ed25519_export_public(self.native_object, key, size)
            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Key encode error", ret)

            return _ffi.buffer(key, size[0])[:]

        def verify(self, signature: bytes, data: BytesOrStr) -> bool:
            """
            Verifies **signature**, using the public key data in the object.

            Returns **True** in case of a valid signature, otherwise **False**.
            """
            data = t2b(data)
            status = _ffi.new("int[1]")

            ret = _lib.wc_ed25519_verify_msg(signature, len(signature),
                                          data, len(data),
                                          status, self.native_object)

            if ret < 0:
                raise WolfCryptApiError("Verify error", ret)

            return status[0] == 1



    class Ed25519Private(Ed25519Public):
        def __init__(self, key: BytesOrStr | None = None, pub: bytes | None = None) -> None:
            _Ed25519.__init__(self)

            self._rng = None

            if key and not pub:
                self.decode_key(key)
            if key and pub:
                self.decode_key(key,pub)

        @classmethod
        def make_key(cls, size: int, rng: Random | None = None) -> Ed25519Private:
            """
            Generates a new key pair of desired length **size**.
            """
            if rng is None:
                rng = Random()
            ed25519 = cls()

            ret = _lib.wc_ed25519_make_key(rng.native_object, size,
                    ed25519.native_object)
            if ret < 0:
                raise WolfCryptApiError("Key generation error", ret)

            # Retain RNG reference defensively; wolfSSL may retain a pointer
            # internally on some builds.
            ed25519._rng = rng

            return ed25519

        @override
        def decode_key(self, key: BytesOrStr, pub: bytes | None = None) -> None:
            """
            Decodes an ED25519 private + pub key
            """
            key = t2b(key)

            if len(key) < _lib.wc_ed25519_priv_size(self.native_object)/2:
                raise WolfCryptError("Key decode error: key too short")

            idx = _ffi.new("word32*")
            idx[0] = 0
            if pub:
                ret = _lib.wc_ed25519_import_private_key(key, len(key), pub,
                        len(pub), self.native_object)
                if ret < 0:
                    raise WolfCryptApiError("Key decode error", ret)
            else:
                ret = _lib.wc_ed25519_import_private_only(key, len(key),
                        self.native_object)
                if ret < 0:
                    raise WolfCryptApiError("Key decode error", ret)
                pubkey = _ffi.new(f"byte[{self.size * 4}]")
                ret = _lib.wc_ed25519_make_public(self.native_object, pubkey,
                        self.size)
                if ret < 0:
                    raise WolfCryptApiError("Public key generate error", ret)
                ret = _lib.wc_ed25519_import_public(pubkey, self.size,
                        self.native_object)
                if ret < 0:
                    raise WolfCryptApiError("Public key import error", ret)

            if self.size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.size})")
            if self.max_signature_size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.max_signature_size})")

        @override
        def encode_key(self) -> tuple[bytes, bytes]:
            """
            Encodes the ED25519 private key.

            Returns the encoded key.
            """
            key = _ffi.new(f"byte[{self.size * 4}]")
            pubkey = _ffi.new(f"byte[{self.size * 4}]")
            priv_size = _ffi.new("word32[1]")
            pub_size = _ffi.new("word32[1]")

            priv_size[0] = _lib.wc_ed25519_priv_size(self.native_object)
            pub_size[0] = _lib.wc_ed25519_pub_size(self.native_object)

            ret = _lib.wc_ed25519_export_private_only(self.native_object,
                    key, priv_size)
            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Private key encode error", ret)
            ret = _lib.wc_ed25519_export_public(self.native_object, pubkey,
                    pub_size)
            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Public key encode error", ret)

            return _ffi.buffer(key, priv_size[0])[:], _ffi.buffer(pubkey, pub_size[0])[:]

        def sign(self, plaintext: BytesOrStr) -> bytes:
            """
            Signs **plaintext**, using the private key data in the object.

            Returns the signature.
            """
            plaintext = t2b(plaintext)
            signature = _ffi.new(f"byte[{self.max_signature_size}]")

            signature_size = _ffi.new("word32[1]")
            signature_size[0] = self.max_signature_size

            ret = _lib.wc_ed25519_sign_msg(plaintext, len(plaintext),
                                        signature, signature_size,
                                        self.native_object)

            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Signature error", ret)

            return _ffi.buffer(signature, signature_size[0])[:]

if _lib.ED448_ENABLED:
    class _Ed448:  # pylint: disable=too-few-public-methods
        def __init__(self) -> None:
            self.native_object = _ffi.new("ed448_key *")
            ret = _lib.wc_ed448_init(self.native_object)
            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("Invalid key error", ret)

        # making sure _lib.wc_ed448_free outlives ed448_key instances
        _delete = staticmethod(_lib.wc_ed448_free)

        def __del__(self) -> None:
            if self.native_object:
                self._delete(self.native_object)

        @property
        def size(self) -> int:
            return _lib.wc_ed448_size(self.native_object)

        @property
        def max_signature_size(self) -> int:
            return _lib.wc_ed448_sig_size(self.native_object)


    class Ed448Public(_Ed448):
        def __init__(self, key: BytesOrStr | None = None) -> None:
            _Ed448.__init__(self)

            if key:
                self.decode_key(key)

        def decode_key(self, key: BytesOrStr) -> None:
            """
            Decodes an ED448 public key
            """
            key = t2b(key)
            if len(key) < _lib.wc_ed448_pub_size(self.native_object):
                raise WolfCryptError("Key decode error: key too short")

            idx = _ffi.new("word32*")
            idx[0] = 0
            ret = _lib.wc_ed448_import_public(key, len(key),
                    self.native_object)
            if ret < 0:
                raise WolfCryptApiError("Key decode error", ret)
            if self.size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.size})")
            if self.max_signature_size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.max_signature_size})")

        def encode_key(self) -> bytes:
            """
            Encodes the ED448 public key

            Returns the encoded key.
            """
            key = _ffi.new(f"byte[{self.size * 4}]")
            size = _ffi.new("word32[1]")

            size[0] = _lib.wc_ed448_pub_size(self.native_object)

            ret = _lib.wc_ed448_export_public(self.native_object, key, size)
            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Key encode error", ret)

            return _ffi.buffer(key, size[0])[:]

        def verify(self, signature: bytes, data: BytesOrStr, ctx: BytesOrStr | None = None) -> bool:
            """
            Verifies **signature**, using the public key data in the object.

            Returns **True** in case of a valid signature, otherwise **False**.
            """
            data = t2b(data)
            status = _ffi.new("int[1]")
            ctx_buf = _ffi.NULL
            ctx_buf_len = 0
            if ctx is not None:
                ctx_buf = t2b(ctx)
                ctx_buf_len = len(ctx_buf)
                if ctx_buf_len > 255:
                    raise ValueError(f"Ed448 ctx must be at most 255 bytes, got {ctx_buf_len}")

            ret = _lib.wc_ed448_verify_msg(signature, len(signature),
                                          data, len(data), status,
                                          self.native_object, ctx_buf,
                                          ctx_buf_len)

            if ret < 0:
                raise WolfCryptApiError("Verify error", ret)

            return status[0] == 1



    class Ed448Private(Ed448Public):
        def __init__(self, key: BytesOrStr | None = None, pub: bytes | None = None) -> None:
            _Ed448.__init__(self)
            self._rng = None

            if key and not pub:
                self.decode_key(key)
            if key and pub:
                self.decode_key(key, pub)

        @classmethod
        def make_key(cls, size: int, rng: Random | None = None) -> Ed448Private:
            """
            Generates a new key pair of desired length **size**.
            """
            if rng is None:
                rng = Random()
            ed448 = cls()

            ret = _lib.wc_ed448_make_key(rng.native_object, size,
                    ed448.native_object)
            if ret < 0:
                raise WolfCryptApiError("Key generation error", ret)

            # Retain RNG reference defensively; wolfSSL may retain a pointer
            # internally on some builds.
            ed448._rng = rng

            return ed448

        @override
        def decode_key(self, key: BytesOrStr, pub: bytes | None = None) -> None:
            """
            Decodes an ED448 private + pub key
            """
            key = t2b(key)

            if len(key) < _lib.wc_ed448_priv_size(self.native_object)/2:
                raise WolfCryptError("Key decode error: key too short")

            idx = _ffi.new("word32*")
            idx[0] = 0
            if pub:
                ret = _lib.wc_ed448_import_private_key(key, len(key), pub,
                        len(pub), self.native_object)
                if ret < 0:
                    raise WolfCryptApiError("Key decode error", ret)
            else:
                ret = _lib.wc_ed448_import_private_only(key, len(key),
                        self.native_object)
                if ret < 0:
                    raise WolfCryptApiError("Key decode error", ret)
                pubkey = _ffi.new(f"byte[{self.size * 4}]")
                ret = _lib.wc_ed448_make_public(self.native_object, pubkey,
                        self.size)
                if ret < 0:
                    raise WolfCryptApiError("Public key generate error", ret)
                ret = _lib.wc_ed448_import_public(pubkey, self.size,
                        self.native_object)
                if ret < 0:
                    raise WolfCryptApiError("Public key import error", ret)

            if self.size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.size})")
            if self.max_signature_size <= 0:  # pragma: no cover
                raise WolfCryptError(f"Key decode error ({self.max_signature_size})")

        @override
        def encode_key(self) -> tuple[bytes, bytes]:
            """
            Encodes the ED448 private key.

            Returns the encoded key.
            """
            key = _ffi.new(f"byte[{self.size * 4}]")
            pubkey = _ffi.new(f"byte[{self.size * 4}]")
            priv_size = _ffi.new("word32[1]")
            pub_size = _ffi.new("word32[1]")

            priv_size[0] = _lib.wc_ed448_priv_size(self.native_object)
            pub_size[0] = _lib.wc_ed448_pub_size(self.native_object)

            ret = _lib.wc_ed448_export_private_only(self.native_object,
                    key, priv_size)
            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Private key encode error", ret)
            ret = _lib.wc_ed448_export_public(self.native_object, pubkey,
                    pub_size)
            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Public key encode error", ret)

            return _ffi.buffer(key, priv_size[0])[:], _ffi.buffer(pubkey, pub_size[0])[:]

        def sign(self, plaintext: BytesOrStr, ctx : BytesOrStr | None = None) -> bytes:
            """
            Signs **plaintext**, using the private key data in the object.

            Returns the signature.
            """
            plaintext = t2b(plaintext)
            signature = _ffi.new(f"byte[{self.max_signature_size}]")

            signature_size = _ffi.new("word32[1]")
            signature_size[0] = self.max_signature_size
            ctx_buf = _ffi.NULL
            ctx_buf_len = 0
            if ctx is not None:
                ctx_buf = t2b(ctx)
                ctx_buf_len = len(ctx_buf)
                if ctx_buf_len > 255:
                    raise ValueError(f"Ed448 ctx must be at most 255 bytes, got {ctx_buf_len}")

            ret = _lib.wc_ed448_sign_msg(plaintext, len(plaintext),
                                        signature, signature_size,
                                        self.native_object, ctx_buf,
                                        ctx_buf_len)

            if ret != 0:  # pragma: no cover
                raise WolfCryptApiError("Signature error", ret)

            return _ffi.buffer(signature, signature_size[0])[:]


if _lib.ML_KEM_ENABLED:
    class MlKemType(IntEnum):
        """
        `MlKemType` specifies supported ML-KEM types.

        `MlKemType` is arguments for constructors and some initialization functions for `MlKemPublic` and `MlKemPrivate`.

        Followings are all possible values:

        - `ML_KEM_512`
        - `ML_KEM_768`
        - `ML_KEM_1024`
        """

        ML_KEM_512 = _lib.WC_ML_KEM_512
        ML_KEM_768 = _lib.WC_ML_KEM_768
        ML_KEM_1024 = _lib.WC_ML_KEM_1024

    class _MlKemBase:
        INVALID_DEVID = _lib.INVALID_DEVID

        def __init__(self, mlkem_type: MlKemType) -> None:
            self.init_done = False
            self.native_object = _ffi.new("KyberKey *")
            ret = _lib.wc_KyberKey_Init(
                mlkem_type, self.native_object, _ffi.NULL, self.INVALID_DEVID
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_Init() error", ret)

            self.init_done = True
            self._rng = None

        def __del__(self) -> None:
            if self.init_done:
                _lib.wc_KyberKey_Free(self.native_object)

        @property
        def ct_size(self) -> int:
            """
            :return: cipher text size in bytes
            :rtype: int
            """
            len = _ffi.new("word32 *")
            ret = _lib.wc_KyberKey_CipherTextSize(self.native_object, len)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_CipherTextSize() error", ret)

            return len[0]

        @property
        def ss_size(self) -> int:
            """
            :return: shared secret size in bytes
            :rtype: int
            """
            len = _ffi.new("word32 *")
            ret = _lib.wc_KyberKey_SharedSecretSize(self.native_object, len)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_SharedSecretSize() error", ret)

            return len[0]

        @property
        def _pub_key_size(self) -> int:
            len = _ffi.new("word32 *")
            ret = _lib.wc_KyberKey_PublicKeySize(self.native_object, len)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_PublicKeySize() error", ret)

            return len[0]

        def _encode_pub_key(self) -> bytes:
            pub_key_size = self._pub_key_size
            pub_key = _ffi.new(f"unsigned char[{pub_key_size}]")
            ret = _lib.wc_KyberKey_EncodePublicKey(
                self.native_object, pub_key, pub_key_size
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_EncodePublicKey() error", ret)

            return _ffi.buffer(pub_key, pub_key_size)[:]

    class MlKemPublic(_MlKemBase):
        @property
        def key_size(self) -> int:
            """
            :return: public key size in bytes
            :rtype: int
            """
            return self._pub_key_size

        def encode_key(self) -> bytes:
            """
            :return: exported public key
            :rtype: bytes
            """
            return self._encode_pub_key()

        def decode_key(self, pub_key: BytesOrStr) -> None:
            """
            :param pub_key: public key to be imported
            :type pub_key: bytes or str
            """
            pub_key_bytestype = t2b(pub_key)
            ret = _lib.wc_KyberKey_DecodePublicKey(
                self.native_object,
                pub_key_bytestype,
                len(pub_key_bytestype),
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_DecodePublicKey() error", ret)

        def encapsulate(self, rng: Random | None = None) -> tuple[bytes, bytes]:
            """
            :param rng: random number generator for an encupsulation
            :type rng: Random
            :return: tuple of a shared secret (first element) and the cipher text (second element)
            :rtype: tuple[bytes, bytes]
            """
            if rng is None:
                rng = Random()
            ct_size = self.ct_size
            ss_size = self.ss_size
            ct = _ffi.new(f"unsigned char[{ct_size}]")
            ss = _ffi.new(f"unsigned char[{ss_size}]")
            ret = _lib.wc_KyberKey_Encapsulate(
                self.native_object, ct, ss, rng.native_object
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_Encapsulate() error", ret)

            return _ffi.buffer(ss, ss_size)[:], _ffi.buffer(ct, ct_size)[:]

        def encapsulate_with_random(self, rand: bytes) -> tuple[bytes, bytes]:
            """
            :param rand: random number for an encapsulation
            :type rand: bytes
            :return: tuple of a shared secret (first element) and the cipher text (second element)
            :rtype: tuple[bytes, bytes]
            """
            ct_size = self.ct_size
            ss_size = self.ss_size
            ct = _ffi.new(f"unsigned char[{ct_size}]")
            ss = _ffi.new(f"unsigned char[{ss_size}]")
            ret = _lib.wc_KyberKey_EncapsulateWithRandom(
                self.native_object, ct, ss, rand, len(rand)
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_EncapsulateWithRandom() error", ret)

            return _ffi.buffer(ss, ss_size)[:], _ffi.buffer(ct, ct_size)[:]

    class MlKemPrivate(_MlKemBase):
        @classmethod
        def make_key(cls, mlkem_type: MlKemType, rng: Random | None = None) -> MlKemPrivate:
            """
            :param mlkem_type: ML-KEM type
            :type mlkem_type: MlKemType
            :param rng: random number generator for a key generation
            :type rng: Random
            :return: `MlKemPrivate` object
            :rtype: MlKemPrivate
            """
            if rng is None:
                rng = Random()
            mlkem_priv = cls(mlkem_type)
            ret = _lib.wc_KyberKey_MakeKey(mlkem_priv.native_object, rng.native_object)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_MakeKey() error", ret)

            # Retain RNG reference defensively.
            mlkem_priv._rng = rng

            return mlkem_priv

        @classmethod
        def make_key_with_random(cls, mlkem_type: MlKemType, rand: bytes) -> MlKemPrivate:
            """
            :param mlkem_type: ML-KEM type
            :type mlkem_type: MlKemType
            :param rand: random number for a key generation
            :type rand: bytes
            :return: `MlKemPrivate` object
            :rtype: MlKemPrivate
            """
            mlkem_priv = cls(mlkem_type)
            ret = _lib.wc_KyberKey_MakeKeyWithRandom(mlkem_priv.native_object, rand, len(rand))

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_MakeKeyWithRandom() error", ret)

            return mlkem_priv

        @property
        def pub_key_size(self) -> int:
            """
            :return: public key size in bytes
            :rtype: int
            """
            return self._pub_key_size

        @property
        def priv_key_size(self) -> int:
            """
            :return: private key size in bytes
            :rtype: int
            """
            len = _ffi.new("word32 *")
            ret = _lib.wc_KyberKey_PrivateKeySize(self.native_object, len)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_PrivateKeySize() error", ret)

            return len[0]

        def encode_pub_key(self) -> bytes:
            """
            :return: exported public key
            :rtype: bytes
            """
            return self._encode_pub_key()

        def encode_priv_key(self) -> bytes:
            """
            :return: exported private key
            :rtype: bytes
            """
            priv_key_size = self.priv_key_size
            priv_key = _ffi.new(f"unsigned char[{priv_key_size}]")
            ret = _lib.wc_KyberKey_EncodePrivateKey(
                self.native_object, priv_key, priv_key_size
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_EncodePrivateKey() error", ret)

            return _ffi.buffer(priv_key, priv_key_size)[:]

        def decode_key(self, priv_key: BytesOrStr) -> None:
            """
            :param priv_key: private key to be imported
            :type priv_key: bytes or str
            """
            priv_key_bytestype = t2b(priv_key)
            ret = _lib.wc_KyberKey_DecodePrivateKey(
                self.native_object,
                priv_key_bytestype,
                len(priv_key_bytestype),
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_DecodePrivateKey() error", ret)

        def decapsulate(self, ct: BytesOrStr) -> bytes:
            """
            :param ct: cipher text
            :type ct: bytes or str
            :return: shared secret
            :rtype: bytes
            """
            ss_size = self.ss_size
            ss = _ffi.new(f"unsigned char[{ss_size}]")
            ct_bytestype = t2b(ct)
            ret = _lib.wc_KyberKey_Decapsulate(
                self.native_object,
                ss,
                ct_bytestype,
                len(ct_bytestype),
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_KyberKey_Decapsulate() error", ret)

            return _ffi.buffer(ss, ss_size)[:]


if _lib.ML_DSA_ENABLED:
    ML_DSA_SIGNATURE_SEED_LENGTH = 32
    """The length of a signature generation seed."""

    class MlDsaType(IntEnum):
        """
        `MlDsaType` specifies supported ML-DSA types.

        `MlDsaType` is arguments for constructors and some initialization functions for `MlDsaPublic` and `MlDsaPrivate`.

        Followings are all possible values:

        - `ML_DSA_44`
        - `ML_DSA_65`
        - `ML_DSA_87`
        """

        ML_DSA_44 = _lib.WC_ML_DSA_44
        ML_DSA_65 = _lib.WC_ML_DSA_65
        ML_DSA_87 = _lib.WC_ML_DSA_87

    class _MlDsaBase:
        INVALID_DEVID = _lib.INVALID_DEVID
        ML_DSA_KEYGEN_SEED_LENGTH = _lib.DILITHIUM_SEED_SZ

        def __init__(self, mldsa_type: MlDsaType) -> None:
            self._init_done = False
            self.native_object = _ffi.new("dilithium_key *")
            ret = _lib.wc_dilithium_init_ex(
                self.native_object, _ffi.NULL, self.INVALID_DEVID
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_dilithium_init_ex() error", ret)

            self._rng = None
            self._init_done = True

            ret = _lib.wc_dilithium_set_level(self.native_object, mldsa_type)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_dilithium_set_level() error", ret)

        def __del__(self) -> None:
            if self._init_done:
                _lib.wc_dilithium_free(self.native_object)

        @property
        def _pub_key_size(self) -> int:
            size = _ffi.new("int *")
            ret = _lib.wc_MlDsaKey_GetPubLen(self.native_object, size)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_MlDsaKey_GetPubLen() error", ret)

            return size[0]

        @property
        def sig_size(self) -> int:
            """
            :return: signature size in bytes
            :rtype: int
            """
            size = _ffi.new("int *")
            ret = _lib.wc_MlDsaKey_GetSigLen(self.native_object, size)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_MlDsaKey_GetSigLen() error", ret)

            return size[0]

        def _decode_pub_key(self, pub_key: BytesOrStr) -> None:
            pub_key_bytestype = t2b(pub_key)
            ret = _lib.wc_dilithium_import_public(
                pub_key_bytestype,
                len(pub_key_bytestype),
                self.native_object,
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_dilithium_import_public() error", ret)

        def _encode_pub_key(self) -> bytes:
            in_size = self._pub_key_size
            pub_key = _ffi.new(f"byte[{in_size}]")
            out_size = _ffi.new("word32 *")
            out_size[0] = in_size
            ret = _lib.wc_dilithium_export_public(self.native_object, pub_key, out_size)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_dilithium_export_public() error", ret)

            if in_size != out_size[0]:
                raise WolfCryptError(f"{in_size=} and {out_size[0]=} don't match")

            return _ffi.buffer(pub_key, out_size[0])[:]

        def verify(self, signature: BytesOrStr, message: BytesOrStr, ctx: BytesOrStr | None = None) -> bool:
            """
            :param signature: signature to be verified
            :type signature: bytes or str
            :param message: message to be verified
            :type message: bytes or str
            :param ctx: context, maximum 255 bytes (optional by default but that requires support for no-context
                signing/verification compiled in; pass empty string "" for FIPS-204 empty-context verification).
            :type ctx: bytes or str. None for no-context verification.
            :return: True if the verification is successful, False otherwise
            :rtype: bool
            """
            if ctx is None and not _lib.ML_DSA_NO_CTX_ENABLED:
                raise WolfCryptError("support for verifying without context is disabled")

            sig_bytestype = t2b(signature)
            msg_bytestype = t2b(message)
            res = _ffi.new("int *")

            if ctx is not None:
                ctx_bytestype = t2b(ctx)
                ret = _lib.wc_dilithium_verify_ctx_msg(
                    sig_bytestype,
                    len(sig_bytestype),
                    ctx_bytestype,
                    len(ctx_bytestype),
                    msg_bytestype,
                    len(msg_bytestype),
                    res,
                    self.native_object,
                )
                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("wc_dilithium_verify_ctx_msg() error", ret)
            else:
                ret = _lib.wc_dilithium_verify_msg(
                    sig_bytestype,
                    len(sig_bytestype),
                    msg_bytestype,
                    len(msg_bytestype),
                    res,
                    self.native_object,
                )
                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("wc_dilithium_verify_msg() error", ret)

            return res[0] == 1

    class MlDsaPrivate(_MlDsaBase):

        @classmethod
        def make_key(cls, mldsa_type: MlDsaType, rng: Random | None = None) -> MlDsaPrivate:
            """
            :param mldsa_type: ML-DSA type
            :type mldsa_type: MlDsaType
            :param rng: random number generator for a key generation
            :type rng: Random
            :return: `MlDsaPrivate` object
            :rtype: MlDsaPrivate
            """
            if rng is None:
                rng = Random()
            mldsa_priv = cls(mldsa_type)
            ret = _lib.wc_dilithium_make_key(
                mldsa_priv.native_object, rng.native_object
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_dilithium_make_key() error", ret)

            # Retain RNG reference defensively.
            mldsa_priv._rng = rng

            return mldsa_priv

        @classmethod
        def make_key_from_seed(cls, mldsa_type: MlDsaType, seed: bytes) -> MlDsaPrivate:
            """
            Deterministically generate the key from a seed.

            :param mldsa_type: ML-DSA type
            :type mldsa_type: MlDsaType
            :param seed: the (32 byte) seed from which to deterministically create the key
            :type seed: bytes
            """
            mldsa_priv = cls(mldsa_type)

            try:
                memoryview(seed)
            except TypeError as exception:
                raise TypeError("seed must support the buffer protocol, such as `bytes` or `bytearray`") from exception

            seed = bytes(seed)

            if len(seed) != cls.ML_DSA_KEYGEN_SEED_LENGTH:
                raise ValueError(f"Seed for generating ML-DSA key must be {cls.ML_DSA_KEYGEN_SEED_LENGTH} bytes")

            ret = _lib.wc_dilithium_make_key_from_seed(mldsa_priv.native_object, seed)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_dilithium_make_key_from_seed() error", ret)

            return mldsa_priv

        @property
        def pub_key_size(self) -> int:
            """
            :return: public key size in bytes
            :rtype: int
            """
            return self._pub_key_size

        @property
        def priv_key_size(self) -> int:
            """
            :return: private key size in bytes
            :rtype: int
            """
            size = _ffi.new("int *")
            ret = _lib.wc_MlDsaKey_GetPrivLen(self.native_object, size)

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_MlDsaKey_GetPrivLen() error", ret)

            return size[0] - self.pub_key_size

        def encode_pub_key(self) -> bytes:
            """
            :return: exported public key
            :rtype: bytes
            """
            return self._encode_pub_key()

        def encode_priv_key(self) -> bytes:
            """
            :return: exported private key
            :rtype: bytes
            """
            in_size = self.priv_key_size
            priv_key = _ffi.new(f"byte[{in_size}]")
            out_size = _ffi.new("word32 *")
            out_size[0] = in_size
            ret = _lib.wc_dilithium_export_private(
                self.native_object, priv_key, out_size
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_dilithium_export_private() error", ret)

            if in_size != out_size[0]:
                raise WolfCryptError(f"{in_size=} and {out_size[0]=} don't match")

            return _ffi.buffer(priv_key, out_size[0])[:]

        def decode_key(self, priv_key: BytesOrStr, pub_key: BytesOrStr | None = None) -> None:
            """
            :param priv_key: private key to be imported
            :type priv_key: bytes or str
            :param pub_key: public key to be imported
            :type pub_key: bytes or str or None
            """
            priv_key_bytestype = t2b(priv_key)
            ret = _lib.wc_dilithium_import_private(
                priv_key_bytestype,
                len(priv_key_bytestype),
                self.native_object,
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("wc_dilithium_import_private() error", ret)

            if pub_key is not None:
                self._decode_pub_key(pub_key)

        def sign(self, message: BytesOrStr, rng: Random | None = None, ctx: BytesOrStr | None = None) -> bytes:
            """
            :param message: message to be signed
            :type message: bytes or str
            :param rng: random number generator for sign
            :type rng: Random
            :param ctx: context, maximum 255 bytes (optional by default but that requires support for no-context
                signing/verification compiled in; pass empty string "" for FIPS-204 empty-context signing).
            :type ctx: bytes or str. None for no-context signing.
            :return: signature
            :rtype: bytes
            """
            if ctx is None and not _lib.ML_DSA_NO_CTX_ENABLED:
                raise WolfCryptError("support for signing without context is disabled")

            if rng is None:
                rng = Random()
            msg_bytestype = t2b(message)
            in_size = self.sig_size
            signature = _ffi.new(f"byte[{in_size}]")
            out_size = _ffi.new("word32 *")
            out_size[0] = in_size

            if ctx is not None:
                ctx_bytestype = t2b(ctx)
                if len(ctx_bytestype) > 255:
                    raise ValueError(f"context length {len(ctx_bytestype)} too large: must be 255 bytes or less")
                ret = _lib.wc_dilithium_sign_ctx_msg(
                    ctx_bytestype,
                    len(ctx_bytestype),  # length must be < 256 bytes
                    msg_bytestype,
                    len(msg_bytestype),
                    signature,
                    out_size,
                    self.native_object,
                    rng.native_object,
                )
                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("wc_dilithium_sign_ctx_msg() error", ret)
            else:
                ret = _lib.wc_dilithium_sign_msg(
                    msg_bytestype,
                    len(msg_bytestype),
                    signature,
                    out_size,
                    self.native_object,
                    rng.native_object,
                )
                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("wc_dilithium_sign_msg() error", ret)

            if in_size != out_size[0]:
                raise WolfCryptError(f"{in_size=} and {out_size[0]=} don't match")

            return _ffi.buffer(signature, out_size[0])[:]

        def sign_with_seed(self, message: BytesOrStr, seed: bytes, ctx: BytesOrStr | None = None) -> bytes:
            """
            :param message: message to be signed
            :type message: bytes or str
            :param seed: 32-byte seed for deterministic signature generation.
            :type seed: bytes
            :param ctx: context, maximum 255 bytes (optional by default but that requires support for no-context
                signing/verification compiled in; pass empty string "" for FIPS-204 empty-context signing).
            :type ctx: bytes or str. None for no-context signing.
            :return: signature
            :rtype: bytes
            """
            if ctx is None and not _lib.ML_DSA_NO_CTX_ENABLED:
                raise WolfCryptError("support for signing without context is disabled")

            msg_bytestype = t2b(message)
            in_size = self.sig_size
            signature = _ffi.new(f"byte[{in_size}]")
            out_size = _ffi.new("word32 *")
            out_size[0] = in_size

            try:
                memoryview(seed)
            except TypeError as exception:
                raise TypeError("seed must support the buffer protocol, such as `bytes` or `bytearray`") from exception

            seed = bytes(seed)

            if len(seed) != ML_DSA_SIGNATURE_SEED_LENGTH:
                raise ValueError(f"Seed for generating a signature must be {ML_DSA_SIGNATURE_SEED_LENGTH} bytes.")

            if ctx is not None:
                ctx_bytestype = t2b(ctx)
                if len(ctx_bytestype) > 255:
                    raise ValueError(
                        f"context length {len(ctx_bytestype)} too large: must be 255 or less"
                    )
                ret = _lib.wc_dilithium_sign_ctx_msg_with_seed(
                    ctx_bytestype,
                    len(ctx_bytestype),  # length must be < 256 bytes
                    msg_bytestype,
                    len(msg_bytestype),
                    signature,
                    out_size,
                    self.native_object,
                    seed,
                )
                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("wc_dilithium_sign_ctx_msg_with_seed() error", ret)
            else:
                ret = _lib.wc_dilithium_sign_msg_with_seed(
                    msg_bytestype,
                    len(msg_bytestype),
                    signature,
                    out_size,
                    self.native_object,
                    seed,
                )
                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("wc_dilithium_sign_msg_with_seed() error", ret)


            if in_size != out_size[0]:
                raise WolfCryptError(f"{in_size=} and {out_size[0]=} don't match")

            return _ffi.buffer(signature, out_size[0])[:]

    class MlDsaPublic(_MlDsaBase):
        @property
        def key_size(self) -> int:
            """
            :return: public key size in bytes
            :rtype: int
            """
            return self._pub_key_size

        def decode_key(self, pub_key: BytesOrStr) -> None:
            """
            :param pub_key: public key to be imported
            :type pub_key: bytes or str
            """
            self._decode_pub_key(pub_key)

        def encode_key(self) -> bytes:
            """
            :return: exported public key
            :rtype: bytes
            """
            return self._encode_pub_key()
