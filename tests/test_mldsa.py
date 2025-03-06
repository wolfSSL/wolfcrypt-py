# test_mldsa.py
#
# Copyright (C) 2025 wolfSSL Inc.
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

from wolfcrypt._ffi import lib as _lib

if _lib.ML_DSA_ENABLED:
    import pytest

    from wolfcrypt.ciphers import MlDsaPrivate, MlDsaPublic, MlDsaType
    from wolfcrypt.random import Random

    @pytest.fixture
    def rng():
        return Random()

    @pytest.fixture(
        params=[MlDsaType.ML_DSA_44, MlDsaType.ML_DSA_65, MlDsaType.ML_DSA_87]
    )
    def mldsa_type(request):
        return request.param

    def test_init_base(mldsa_type):
        mldsa_priv = MlDsaPrivate(mldsa_type)
        assert isinstance(mldsa_priv, MlDsaPrivate)

        mldsa_pub = MlDsaPublic(mldsa_type)
        assert isinstance(mldsa_pub, MlDsaPublic)

    def test_size_properties(mldsa_type):
        refvals = {
            MlDsaType.ML_DSA_44: {
                "sig_size": 2420,
                "pub_key_size": 1312,
                "priv_key_size": 2560,
            },
            MlDsaType.ML_DSA_65: {
                "sig_size": 3309,
                "pub_key_size": 1952,
                "priv_key_size": 4032,
            },
            MlDsaType.ML_DSA_87: {
                "sig_size": 4627,
                "pub_key_size": 2592,
                "priv_key_size": 4896,
            },
        }

        mldsa_pub = MlDsaPublic(mldsa_type)
        assert mldsa_pub.sig_size == refvals[mldsa_type]["sig_size"]
        assert mldsa_pub.key_size == refvals[mldsa_type]["pub_key_size"]

        mldsa_priv = MlDsaPrivate(mldsa_type)
        assert mldsa_priv.sig_size == refvals[mldsa_type]["sig_size"]
        assert mldsa_priv.pub_key_size == refvals[mldsa_type]["pub_key_size"]
        assert mldsa_priv.priv_key_size == refvals[mldsa_type]["priv_key_size"]

    def test_initializations(mldsa_type, rng):
        mldsa_priv = MlDsaPrivate.make_key(mldsa_type, rng)
        assert type(mldsa_priv) is MlDsaPrivate

        mldsa_priv2 = MlDsaPrivate(mldsa_type)
        assert type(mldsa_priv2) is MlDsaPrivate

        mldsa_pub = MlDsaPublic(mldsa_type)
        assert type(mldsa_pub) is MlDsaPublic

    def test_key_import_export(mldsa_type, rng):
        # Generate key pair and export keys
        mldsa_priv = MlDsaPrivate.make_key(mldsa_type, rng)
        priv_key = mldsa_priv.encode_priv_key()
        pub_key = mldsa_priv.encode_pub_key()
        assert len(priv_key) == mldsa_priv.priv_key_size
        assert len(pub_key) == mldsa_priv.pub_key_size

        # Export key pair from imported one
        mldsa_priv2 = MlDsaPrivate(mldsa_type)
        mldsa_priv2.decode_key(priv_key, pub_key)
        priv_key2 = mldsa_priv2.encode_priv_key()
        pub_key2 = mldsa_priv2.encode_pub_key()
        assert priv_key == priv_key2
        assert pub_key == pub_key2

        # Export private key from imported one
        mldsa_priv3 = MlDsaPrivate(mldsa_type)
        mldsa_priv3.decode_key(priv_key)
        priv_key3 = mldsa_priv3.encode_priv_key()
        assert priv_key == priv_key3

        # Export public key from imported one
        mldsa_pub = MlDsaPublic(mldsa_type)
        mldsa_pub.decode_key(pub_key)
        pub_key3 = mldsa_pub.encode_key()
        assert pub_key == pub_key3

    def test_sign_verify(mldsa_type, rng):
        # Generate a key pair and export public key
        mldsa_priv = MlDsaPrivate.make_key(mldsa_type, rng)
        pub_key = mldsa_priv.encode_pub_key()

        # Import public key
        mldsa_pub = MlDsaPublic(mldsa_type)
        mldsa_pub.decode_key(pub_key)

        # Sign a message
        message = b"This is a test message for ML-DSA signature"
        signature = mldsa_priv.sign(message, rng)
        assert len(signature) == mldsa_priv.sig_size

        # Verify the signature by MlDsaPrivate
        assert mldsa_priv.verify(signature, message)

        # Verify the signature by MlDsaPublic
        assert mldsa_pub.verify(signature, message)

        # Verify with wrong message
        wrong_message = b"This is a wrong message for ML-DSA signature"
        assert not mldsa_pub.verify(signature, wrong_message)
