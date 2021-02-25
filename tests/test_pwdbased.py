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
        vectors.append(TestVector(
            password="pass1234",
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
