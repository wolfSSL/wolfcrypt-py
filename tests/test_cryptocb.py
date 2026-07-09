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

import pytest
from typing_extensions import override

from wolfcrypt._ffi import lib as _lib
from wolfcrypt.random import Random

if _lib.SHA_ENABLED:
    from wolfcrypt.hashes import Sha

if not _lib.CRYPTO_CB_ENABLED:
    pytest.skip("Crypto Callbacks not supported", allow_module_level=True)

from wolfcrypt.cryptocb import CryptoCallback


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
        return struct.pack("I16x", len(b"".join(self.data)))


if _lib.SHA_ENABLED:
    def test_hash_callback():
        with HashCryptoCallback(11):
            sha = Sha(device_id=11)
            sha.update(bytes(10))
            sha.update(bytes(5))
            digest = sha.digest()
            assert digest == struct.pack("I16x", 15)
