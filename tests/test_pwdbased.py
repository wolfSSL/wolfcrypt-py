# test_pwdbased.py
#
# Copyright (C) 2006-2022 wolfSSL Inc.
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

# pylint: disable=redefined-outer-name
from collections import namedtuple
import pytest
from wolfcrypt._ffi import lib as _lib

if _lib.PWDBASED_ENABLED:
    from wolfcrypt.pwdbased import PBKDF2

if _lib.SHA_ENABLED:
    from wolfcrypt.hashes import Sha
    if _lib.HMAC_ENABLED:
        from wolfcrypt.hashes import HmacSha

@pytest.fixture
def pbkdf2_vectors():
    TestVector = namedtuple("TestVector", """password salt iterations key_length
                                             hash_type""")
    TestVector.__new__.__defaults__ = (None,) * len(TestVector._fields)

    vectors = []

    if _lib.PWDBASED_ENABLED and _lib.SHA_ENABLED and _lib.HMAC_ENABLED:
        # HMAC requires a key, which in this case is the password. Do not
        # shorten the length of the password below the FIPS requirement.
        # See HMAC_FIPS_MIN_KEY.
        vectors.append(TestVector(
            password="wolfcrypt is the best crypto around",
            salt="salt1234",
            iterations=1000,
            key_length=Sha.digest_size,
            hash_type=HmacSha._type
        ))

    return vectors

def test_pbkdf2(pbkdf2_vectors):
    for vector in pbkdf2_vectors:
        key = PBKDF2(vector.password, vector.salt, vector.iterations,
                     vector.key_length, vector.hash_type)
        assert len(key) == vector.key_length
