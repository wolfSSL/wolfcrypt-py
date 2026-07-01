# test_random.py
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# pylint: disable=redefined-outer-name

import pytest
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.random import Random


@pytest.fixture
def rng():
    return Random()


def test_byte(rng):
    assert len(rng.byte()) == 1


def test_bytes(rng):
    assert len(rng.bytes(1)) == 1
    assert len(rng.bytes(8)) == 8
    assert len(rng.bytes(128)) == 128


@pytest.fixture
def rng_nonce():
    return Random(b"abcdefghijklmnopqrstuv")


def test_nonce_byte(rng_nonce):
    assert len(rng_nonce.byte()) == 1


@pytest.mark.parametrize("length", (1, 8, 128))
def test_nonce_bytes(rng_nonce, length):
    assert len(rng_nonce.bytes(length)) == length


@pytest.mark.skipif(not _lib.HASHDRBG_ENABLED, reason="Reseeding only available with hash-DRBG")
@pytest.mark.parametrize("seed_size", [0, 1, 32, 1000])
def test_reseed_sizes(rng, seed_size):
    """
    Test that reseeding the random number generator works, for various seed sizes.
    """
    # Create seed of required length.
    seed = bytes(x % 256 for x in range(seed_size))
    assert len(seed) == seed_size
    rng.reseed(seed)
    # Pull some bytes from the random number generator to test that it still works.
    rng.bytes(32)


@pytest.mark.skipif(not _lib.HASHDRBG_ENABLED, reason="Reseeding only available with hash-DRBG")
def test_reseed_multiple(rng):
    """
    Test that consecutive reseeding of the random number generator works.
    """
    for _ in range(10):
        # Create seed of typical size. Testing with various seed sizes done in `test_reseed_sizes`.
        seed = bytes(x % 256 for x in range(32))
        rng.reseed(seed)

    # Pull some bytes from the random number generator to test that it still works.
    rng.bytes(100)
