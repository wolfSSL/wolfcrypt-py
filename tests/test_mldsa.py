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

if hasattr(_lib, "ML_DSA_ENABLED") and _lib.ML_DSA_ENABLED:
    from binascii import unhexlify as h2b

    import pytest

    from wolfcrypt.mldsa import MlDsaPrivate, MlDsaPublic, MlDsaType
    from wolfcrypt.random import Random

    @pytest.fixture
    def rng():
        return Random()

    @pytest.fixture(params=[MlDsaType.ML_DSA_44, MlDsaType.ML_DSA_65, MlDsaType.ML_DSA_87])
    def mldsa_type(request):
        return request.param

    def test_init_base(mldsa_type):
        mldsa_priv = MlDsaPrivate(mldsa_type)
        assert isinstance(mldsa_priv, MlDsaPrivate)

        mldsa_pub = MlDsaPublic(mldsa_type)
        assert isinstance(mldsa_pub, MlDsaPublic)

    def test_key_sizes(mldsa_type):
        mldsa_priv = MlDsaPrivate(mldsa_type)

        # Check that key sizes are returned correctly
        assert mldsa_priv.priv_key_size > 0
        assert mldsa_priv.pub_key_size > 0
        assert mldsa_priv.sig_size > 0

        # Public key should have the same pub_key_size
        mldsa_pub = MlDsaPublic(mldsa_type)
        assert mldsa_pub.pub_key_size == mldsa_priv.pub_key_size
        assert mldsa_pub.sig_size == mldsa_priv.sig_size

    """
    def test_key_generation(mldsa_type, rng):
        # Test key generation
        mldsa_priv = MlDsaPrivate.make_key(mldsa_type, rng)
        assert isinstance(mldsa_priv, MlDsaPrivate)

        # Export keys
        priv_key = mldsa_priv.encode_priv_key()
        pub_key = mldsa_priv.encode_pub_key()

        # Check key sizes
        assert len(priv_key) == mldsa_priv.priv_key_size
        assert len(pub_key) == mldsa_priv.pub_key_size
    """

    """
    def test_key_import_export(mldsa_type, rng):
        # Generate a key pair
        mldsa_priv = MlDsaPrivate.make_key(mldsa_type, rng)

        # Export keys
        priv_key = mldsa_priv.encode_priv_key()
        pub_key = mldsa_priv.encode_pub_key()

        # Import private key
        mldsa_priv2 = MlDsaPrivate(mldsa_type)
        mldsa_priv2.decode_key(priv_key)

        # Export keys from imported private key
        priv_key2 = mldsa_priv2.encode_priv_key()
        pub_key2 = mldsa_priv2.encode_pub_key()

        # Keys should match
        assert priv_key == priv_key2
        assert pub_key == pub_key2

        # Import public key
        mldsa_pub = MlDsaPublic(mldsa_type)
        mldsa_pub.decode_key(pub_key)

        # Export public key from imported public key
        pub_key3 = mldsa_pub.encode_key()

        # Public keys should match
        assert pub_key == pub_key3
    """

    def test_sign_verify(mldsa_type, rng):
        # Generate a key pair
        mldsa_priv = MlDsaPrivate.make_key(mldsa_type, rng)

        # Export public key
        pub_key = mldsa_priv.encode_pub_key()

        # Import public key
        mldsa_pub = MlDsaPublic(mldsa_type)
        mldsa_pub.decode_key(pub_key)

        # Sign a message
        message = b"This is a test message for ML-DSA signature"
        signature = mldsa_priv.sign(message, rng)

        # Verify the signature
        assert mldsa_pub.verify(signature, message)

        # Verify with wrong message
        wrong_message = b"This is a wrong message for ML-DSA signature"
        assert not mldsa_pub.verify(signature, wrong_message)

    """
    def test_der_encoding(mldsa_type, rng):
        # Generate a key pair
        mldsa_priv = MlDsaPrivate.make_key(mldsa_type, rng)

        # Export keys in DER format
        priv_key_der = mldsa_priv.encode_priv_key_der()
        pub_key_der = mldsa_priv.encode_pub_key_der()

        # Check that DER encoded keys are longer than raw keys
        assert len(priv_key_der) > mldsa_priv.priv_key_size
        assert len(pub_key_der) > mldsa_priv.pub_key_size

        # Test public key DER encoding from public key object
        mldsa_pub = MlDsaPublic(mldsa_type)
        mldsa_pub.decode_key(mldsa_priv.encode_pub_key())
        pub_key_der2 = mldsa_pub.encode_key_der()

        # DER encoded public keys should match
        assert pub_key_der == pub_key_der2
    """
