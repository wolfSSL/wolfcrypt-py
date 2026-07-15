# test_cryptocb.py
#
# Copyright (C) 2026 wolfSSL Inc.
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
# ty: ignore[possibly-missing-import]

from __future__ import annotations

import struct
from binascii import hexlify as b2h

import pytest
from typing_extensions import override

from wolfcrypt._ffi import lib as _lib
from wolfcrypt.exceptions import WolfCryptApiError
from wolfcrypt.hashes import _Sha
from wolfcrypt.random import Random

if not _lib.CRYPTO_CB_ENABLED:
    pytest.skip("Crypto Callbacks not supported", allow_module_level=True)

from wolfcrypt.cryptocb import CryptoCallback, DIGEST_SIZE

SHA_CLASSES: list[type[_Sha]] = []

if _lib.SHA_ENABLED:
    from wolfcrypt.hashes import Sha
    SHA_CLASSES.append(Sha)

if _lib.SHA256_ENABLED:
    from wolfcrypt.hashes import Sha256
    SHA_CLASSES.append(Sha256)

if _lib.SHA384_ENABLED:
    from wolfcrypt.hashes import Sha384
    SHA_CLASSES.append(Sha384)

if _lib.SHA512_ENABLED:
    from wolfcrypt.hashes import Sha512
    SHA_CLASSES.append(Sha512)

if _lib.SHA3_ENABLED:
    from wolfcrypt.hashes import Sha3
    SHA_CLASSES.append(Sha3)


def test_default_device_id():
    # In the python implementation the default device ID is the invalid device ID.
    assert CryptoCallback.default_device_id() == _lib.INVALID_DEVID


class RngCryptoCallback(CryptoCallback):
    @override
    def rng_callback(self, device_id: int, rng: _lib.RNG, size: int) -> bytes:
        # Generate fake random data for testing purposes.
        return bytes(range(1, 1 + size))


def test_rng_callback():
    with RngCryptoCallback(10):
        rng = Random(device_id=10)

        random = rng.byte()
        assert random == b"\01"

        random = rng.bytes(1)
        assert random == b"\01"

        random = rng.bytes(3)
        assert random == b"\01\02\03"


class HashCryptoCallback(CryptoCallback):
    def __init__(self, device_id):
        super().__init__(device_id)
        self.data: list[bytes] = []

    @override
    def hash_update_callback(self, device_id: int, hash_type: int, data: bytes) -> None:
        self.data.append(data)

    @override
    def hash_finalize_callback(self, device_id: int, hash_type: int) -> bytes:
        # quite lame hash function, just returns the length of the data as an integer (padded to match the expected hash length).
        return struct.pack(f"I{DIGEST_SIZE[hash_type] - 4}x", len(b"".join(self.data)))


@pytest.mark.parametrize("sha_cls", SHA_CLASSES)
def test_hash_callback(sha_cls: type[_Sha]) -> None:
    with HashCryptoCallback(11):
        sha = sha_cls(device_id=11)
        sha.update(bytes(10))
        sha.update(bytes(5))
        digest = sha.digest()
        digest_size = sha.digest_size
        assert digest_size is not None
        assert digest == struct.pack(f"I{digest_size - 4}x", 15)


class BadHashCryptoCallback(CryptoCallback):
    @override
    def hash_finalize_callback(self, device_id: int, hash_type: int) -> bytes:
        return bytes(1)  # bad hash length


if _lib.SHA_ENABLED:
    def test_hash_callback_failure():
        with BadHashCryptoCallback(12):
            sha = Sha(device_id=12)
            sha.update(bytes(10))
            with pytest.raises(WolfCryptApiError):
                sha.digest()


if _lib.AESGCM_STREAM_ENABLED:
    from wolfcrypt.ciphers import AesGcmStream

    def test_crypto_callback_aes_gcm_stream_encrypt():
        """Verify that the crypto callback that does not support AesGcmStream works as if not callback was installed."""
        with CryptoCallback(13):
            """Known answer encrypt-decrypt test with default authentication tag size of 16 bytes"""
            key = "fedcba9876543210"
            iv = "0123456789abcdef"
            gcm = AesGcmStream(key, iv, device_id=13)
            buf = gcm.encrypt("hello world")
            authTag = gcm.final()
            assert authTag is not None
            assert b2h(authTag) == bytes('ac8fcee96dc6ef8e5236da19b6197d2e', 'utf-8')
            assert b2h(buf) == bytes('5ba7d42e1bf01d7998e932', "utf-8")
