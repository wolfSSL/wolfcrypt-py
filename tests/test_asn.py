from collections import namedtuple
import pytest
import os
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.utils import h2b

if _lib.ASN_ENABLED:
    from wolfcrypt.asn import pem_to_der, der_to_pem
if _lib.SHA256_ENABLED:
    from wolfcrypt.hashes import Sha256
if _lib.RSA_ENABLED:
    from wolfcrypt.ciphers import RsaPrivate, RsaPublic

certs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

@pytest.fixture
def pem_der_conversion_vectors():
    TestVector = namedtuple("TestVector", "pem der type")
    TestVector.__new__.__defaults__ = (None,) * len(TestVector._fields)

    vectors = []

    if _lib.ASN_ENABLED:
        files = [
            ("server-key.pem", "server-key.der", _lib.PRIVATEKEY_TYPE),
            ("server-cert.pem", "server-cert.der", _lib.CERT_TYPE),
        ]
        for f in files:
            pem_path = os.path.join(certs_dir, f[0])
            with open(pem_path, "rb") as pem_handle:
                pem = pem_handle.read()

            der_path = os.path.join(certs_dir, f[1])
            with open(der_path, "rb") as der_handle:
                der = der_handle.read()

            vectors.append(TestVector(pem=pem, der=der, type=f[2]))

        return vectors

def test_pem_der_conversion(pem_der_conversion_vectors):
    for vector in pem_der_conversion_vectors:
        computed_der = pem_to_der(vector.pem, vector.type)
        assert computed_der == vector.der

        computed_pem = der_to_pem(vector.der, vector.type)
        assert computed_pem == vector.pem
