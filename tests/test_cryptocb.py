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

import pytest

from wolfcrypt._ffi import lib as _lib
from wolfcrypt.random import Random


if not _lib.CRYPTO_CB_ENABLED:
    pytest.skip("Crypto Callbacks not supported", allow_module_level=True)

from wolfcrypt.cryptocb import CryptoCallback


def test_default_device_id():
    print(f"Default device ID = {CryptoCallback.default_device_id()}")

class RngCryptoCallback(CryptoCallback):
    def rng_callback(self, _device_id: int, _rng, size: int) -> bytes:
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
