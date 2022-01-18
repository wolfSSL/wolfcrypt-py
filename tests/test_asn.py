# test_asn.py
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
import os
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.utils import h2b

if _lib.ASN_ENABLED:
    from wolfcrypt.asn import pem_to_der, der_to_pem, make_signature, check_signature
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

@pytest.fixture
def signature_vectors():
    TestVector = namedtuple("TestVector", """data signature hash_cls pub_key
                                             priv_key""")
    TestVector.__new__.__defaults__ = (None,) * len(TestVector._fields)

    vectors = []

    with open(os.path.join(certs_dir, "server-keyPub.pem"), "rb") as f:
        pub_key_pem = f.read()
    with open(os.path.join(certs_dir, "server-key.pem"), "rb") as f:
        priv_key_pem = f.read()

    # Signature computed with:
    # echo -n "wolfcrypt is the best crypto around" | \
    # openssl dgst -hex -sha256 -sign tests/certs/server-key.pem
    if _lib.ASN_ENABLED and _lib.SHA256_ENABLED and _lib.RSA_ENABLED:
        vectors.append(TestVector(
            data="wolfcrypt is the best crypto around",
            signature=h2b("1d65f21df8fdc9f3c2351792840423481c6b0f2332105abd9248"
                          "9e0dc8f6f8c740e267cf49f522f771eabd484f961eaf9f907c97"
                          "b513bb9de7411b508c4e7ab7dc4438890ca161a9e24addaffd3c"
                          "86821f2431f55fde5d131dfbe5805dea74e8882bfbfbf451f809"
                          "ed792dfb0b17c799e6a39f866ed9cf613138c9e5e99f757ea13a"
                          "2b9c167c294cd89f38365ab40175d4e29c24d672cd5ad2d57fec"
                          "e9ea2b29c1866235c791ec5b635b858512c2b832b1b8f1dc6854"
                          "cd4927df5519eefee439848c7f109548b3a3c8265658e009899a"
                          "51a4edaf9f1199f93e448482f27c43a53e0bc65b04e9848128e3"
                          "60314e864190e6bb9812bfbf4b40994f2c1d4ca7aad9"),
            hash_cls=Sha256,
            pub_key=RsaPublic.from_pem(pub_key_pem),
            priv_key=RsaPrivate.from_pem(priv_key_pem)
        ))

    return vectors

def test_pem_der_conversion(pem_der_conversion_vectors):
    for vector in pem_der_conversion_vectors:
        computed_der = pem_to_der(vector.pem, vector.type)
        assert computed_der == vector.der

        computed_pem = der_to_pem(vector.der, vector.type)
        assert computed_pem == vector.pem

def test_signature(signature_vectors):
    for vector in signature_vectors:
        assert make_signature(vector.data, vector.hash_cls, vector.priv_key) == vector.signature
        assert check_signature(vector.signature, vector.data, vector.hash_cls,
                               vector.pub_key)
