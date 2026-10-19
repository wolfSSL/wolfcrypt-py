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

import gc
import hashlib
import struct
from binascii import hexlify as b2h
from typing import Any

import pytest
from typing_extensions import override

from wolfcrypt._ffi import lib as _lib
from wolfcrypt.exceptions import WolfCryptApiError
from wolfcrypt.hashes import _Sha
from wolfcrypt.random import Random

if not _lib.CRYPTO_CB_ENABLED:
    pytest.skip("Crypto Callbacks not supported", allow_module_level=True)

from wolfcrypt.cryptocb import CryptoCallback, DIGEST_SIZE

HASH_CB_ENABLED = _lib.CRYPTO_CB_COPY_ENABLED and _lib.CRYPTO_CB_FREE_ENABLED
needs_hash_cb = pytest.mark.skipif(not HASH_CB_ENABLED, reason="Hash callbacks need copy and free crypto callbacks")

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
    @override
    def hash_update_callback(self, device_id: int, hash_type: int, context: dict[str, Any], data: bytes) -> None:
        context.setdefault("data", []).append(data)

    @override
    def hash_finalize_callback(self, device_id: int, hash_type: int, context: dict[str, Any]) -> bytes:
        # quite lame hash function, just returns the length of the data as an integer (padded to match the expected hash length).
        return struct.pack(f"I{DIGEST_SIZE[hash_type] - 4}x", len(b"".join(context.get("data", []))))


def fake_digest(sha: _Sha, length: int) -> bytes:
    assert sha.digest_size is not None
    return struct.pack(f"I{sha.digest_size - 4}x", length)


@needs_hash_cb
@pytest.mark.parametrize("sha_cls", SHA_CLASSES)
def test_hash_callback(sha_cls: type[_Sha]) -> None:
    with HashCryptoCallback(11):
        sha = sha_cls(device_id=11)
        sha.update(bytes(10))
        sha.update(bytes(5))
        assert sha.digest() == fake_digest(sha, 15)


@needs_hash_cb
@pytest.mark.parametrize("sha_cls", SHA_CLASSES)
def test_hash_callback_interleaved(sha_cls: type[_Sha]) -> None:
    with HashCryptoCallback(20):
        first = sha_cls(device_id=20)
        second = sha_cls(device_id=20)
        first.update(bytes(10))
        second.update(bytes(5))
        assert first.digest() == fake_digest(first, 10)
        assert second.digest() == fake_digest(second, 5)


@needs_hash_cb
@pytest.mark.parametrize("sha_cls", SHA_CLASSES)
def test_hash_callback_copy(sha_cls: type[_Sha]) -> None:
    with HashCryptoCallback(21):
        sha = sha_cls(device_id=21)
        sha.update(bytes(10))
        dup = sha.copy()
        dup.update(bytes(5))
        assert sha.digest() == fake_digest(sha, 10)
        assert dup.digest() == fake_digest(dup, 15)
        # digest() finalizes a temporary copy, so the original keeps its state
        sha.update(bytes(1))
        assert sha.digest() == fake_digest(sha, 11)
        assert dup.digest() == fake_digest(dup, 15)


@needs_hash_cb
@pytest.mark.parametrize("sha_cls", SHA_CLASSES)
def test_hash_callback_free_drops_context(sha_cls: type[_Sha]) -> None:
    with HashCryptoCallback(22) as cb:
        sha = sha_cls(device_id=22)
        sha.update(bytes(3))
        dup = sha.copy()
        assert sha.digest() == fake_digest(sha, 3)
        assert len(cb._hash_contexts) == 2
        del sha, dup
        gc.collect()
        assert not cb._hash_contexts


class BadHashCryptoCallback(CryptoCallback):
    @override
    def hash_update_callback(self, device_id: int, hash_type: int, context: dict[str, Any], data: bytes) -> None:
        pass

    @override
    def hash_finalize_callback(self, device_id: int, hash_type: int, context: dict[str, Any]) -> bytes:
        return bytes(1)  # bad hash length


if _lib.SHA_ENABLED:
    @needs_hash_cb
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


class BadRngCryptoCallback(CryptoCallback):
    @override
    def rng_callback(self, device_id: int, rng: _lib.RNG, size: int) -> bytes:
        return bytes(1)  # bad random length


def test_rng_callback_failure():
    with BadRngCryptoCallback(14):
        rng = Random(device_id=14)
        with pytest.raises(WolfCryptApiError):
            rng.bytes(4)


def test_reregister_same_device_id():
    gc.disable()
    try:
        with RngCryptoCallback(15):
            pass
        # A stale instance collected later must not unregister the new owner.
        with RngCryptoCallback(15):
            gc.collect()
            assert Random(device_id=15).bytes(3) == b"\01\02\03"
        # Replacing a live registration hands the device id to the new instance.
        first = RngCryptoCallback(15)
        with RngCryptoCallback(15):
            del first
            gc.collect()
            assert Random(device_id=15).bytes(3) == b"\01\02\03"
    finally:
        gc.enable()


class FinalizeOnlyCryptoCallback(CryptoCallback):
    @override
    def hash_finalize_callback(self, device_id: int, hash_type: int, context: dict[str, Any]) -> bytes:
        return bytes(DIGEST_SIZE[hash_type])


if _lib.SHA256_ENABLED:
    def test_hash_partial_override_falls_back():
        with FinalizeOnlyCryptoCallback(16):
            sha = Sha256(b"abc", device_id=16)
            assert sha.digest() == hashlib.sha256(b"abc").digest()

    @pytest.mark.skipif(HASH_CB_ENABLED, reason="Copy and free crypto callbacks are available")
    def test_hash_without_copy_free_falls_back():
        with HashCryptoCallback(23):
            sha = Sha256(b"abc", device_id=23)
            assert sha.digest() == hashlib.sha256(b"abc").digest()

    @needs_hash_cb
    def test_hash_new_device_id():
        with HashCryptoCallback(17):
            sha = Sha256.new(bytes(7), device_id=17)
            assert sha.digest() == struct.pack("I28x", 7)


if _lib.SHA3_ENABLED:
    def test_hash_unsupported_type_falls_back():
        with HashCryptoCallback(18):
            sha = Sha3(b"abc", size=Sha3.SHA3_224_DIGEST_SIZE, device_id=18)
            assert sha.digest() == hashlib.sha3_224(b"abc").digest()


if _lib.HMAC_ENABLED and _lib.SHA256_ENABLED:
    from wolfcrypt.hashes import HmacSha256

    class RecordingCryptoCallback(CryptoCallback):
        def __init__(self, device_id: int) -> None:
            super().__init__(device_id)
            self.algo_types: list[int] = []

        @override
        def callback(self, device_id: int, info: _lib.wc_CryptoInfo) -> int:
            self.algo_types.append(info.algo_type)
            return super().callback(device_id, info)

    def test_hmac_device_id():
        with RecordingCryptoCallback(19) as cb:
            mac = HmacSha256.new(b"key", b"data", device_id=19).digest()
        assert mac == HmacSha256(b"key", b"data").digest()
        assert cb.algo_types
