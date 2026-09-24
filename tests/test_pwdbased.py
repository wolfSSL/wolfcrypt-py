# test_pwdbased.py
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
# ty: ignore[possibly-missing-import]

from collections import namedtuple
import importlib.util
import pytest
from wolfcrypt import pwdbased
from wolfcrypt._ffi import lib as _lib

if _lib.PBKDF2_ENABLED:
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

    if _lib.PBKDF2_ENABLED and _lib.SHA_ENABLED and _lib.HMAC_ENABLED:
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

def test_pbkdf2_defined_only_when_enabled(monkeypatch):
    """F-12232: PBKDF2 needs wc_PBKDF2 in the linked wolfSSL."""
    assert hasattr(pwdbased, "PBKDF2") == bool(_lib.PBKDF2_ENABLED)

    # Load a fresh copy of the module as if wc_PBKDF2 were not compiled in.
    monkeypatch.setattr(_lib, "PBKDF2_ENABLED", 0)
    spec = importlib.util.find_spec("wolfcrypt.pwdbased")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert not hasattr(module, "PBKDF2")
