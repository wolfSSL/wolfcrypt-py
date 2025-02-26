# mldsa.py
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

from enum import IntEnum

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.utils import t2b
from wolfcrypt.random import Random
from wolfcrypt.exceptions import WolfCryptError

if hasattr(_lib, "wc_dilithium_init_ex"):
    class MlDsaType(IntEnum):
        """
        `MlDsaType` specifies supported ML-DSA types.

        `MlDsaType` is arguments for constructors and some initialization functions for `MlDsaPublic` and `MlDsaPrivate`.

        Followings are all possible values:

        - `ML_DSA_44`
        - `ML_DSA_65`
        - `ML_DSA_87`
        """

        ML_DSA_44 = _lib.WC_ML_DSA_44
        ML_DSA_65 = _lib.WC_ML_DSA_65
        ML_DSA_87 = _lib.WC_ML_DSA_87

    class _MlDsaBase(object):
        INVALID_DEVID = _lib.INVALID_DEVID

        def __init__(self, mldsa_type):
            self.init_done = False
            self.native_object = _ffi.new("dilithium_key *")
            ret = _lib.wc_dilithium_init_ex(
                self.native_object, _ffi.NULL, self.INVALID_DEVID
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_init_ex() error (%d)" % ret)

            ret = _lib.wc_dilithium_set_level(self.native_object, mldsa_type)

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_set_level() error (%d)" % ret)

            self.init_done = True

        def __del__(self):
            if self.init_done:
                _lib.wc_dilithium_free(self.native_object)

        @property
        def priv_key_size(self):
            """
            :return: private key size in bytes
            :rtype: int
            """
            ret = _lib.wc_dilithium_priv_size(self.native_object)

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_priv_size() error (%d)" % ret)

            return ret

        @property
        def pub_key_size(self):
            """
            :return: public key size in bytes
            :rtype: int
            """
            ret = _lib.wc_dilithium_pub_size(self.native_object)

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_pub_size() error (%d)" % ret)

            return ret

        @property
        def sig_size(self):
            """
            :return: signature size in bytes
            :rtype: int
            """
            ret = _lib.wc_dilithium_sig_size(self.native_object)

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_sig_size() error (%d)" % ret)

            return ret

        def _encode_pub_key(self):
            pub_key_size = self.pub_key_size
            pub_key = _ffi.new(f"unsigned char[{pub_key_size}]")
            out_len = _ffi.new("word32 *")
            out_len[0] = pub_key_size
            ret = _lib.wc_dilithium_export_public(
                self.native_object, pub_key, out_len
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_export_public() error (%d)" % ret)

            return _ffi.buffer(pub_key, out_len[0])[:]

        def _encode_pub_key_der(self, with_alg=1):
            pub_key_size = self.pub_key_size
            # DER encoding adds some overhead
            der_size = pub_key_size + 50
            output = _ffi.new(f"unsigned char[{der_size}]")
            # Use export_public instead of PublicKeyToDer since there's no direct equivalent
            out_len = _ffi.new("word32 *")
            out_len[0] = der_size
            ret = _lib.wc_dilithium_export_public(
                self.native_object, output, out_len
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_export_public() error (%d)" % ret)

            return _ffi.buffer(output, ret)[:]

    class MlDsaPrivate(_MlDsaBase):
        @classmethod
        def make_key(cls, mldsa_type, rng=Random()):
            """
            :param mldsa_type: ML-DSA type
            :type mldsa_type: MlDsaType
            :param rng: random number generator for a key generation
            :type rng: Random
            :return: `MlDsaPrivate` object
            :rtype: MlDsaPrivate
            """
            mldsa_priv = cls(mldsa_type)
            ret = _lib.wc_dilithium_make_key(mldsa_priv.native_object, rng.native_object)

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_make_key() error (%d)" % ret)

            return mldsa_priv

        def decode_key(self, priv_key):
            """
            :param priv_key: private key to be imported
            :type priv_key: bytes or str
            """
            priv_key_bytestype = t2b(priv_key)
            ret = _lib.wc_dilithium_import_private(
                _ffi.from_buffer(priv_key_bytestype),
                len(priv_key_bytestype),
                self.native_object
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_import_private() error (%d)" % ret)

        def encode_pub_key(self):
            """
            :return: exported public key
            :rtype: bytes
            """
            return self._encode_pub_key()

        def encode_pub_key_der(self, with_alg=1):
            """
            :return: exported public key in DER format
            :rtype: bytes
            """
            return self._encode_pub_key_der(with_alg)

        def encode_priv_key(self):
            """
            :return: exported private key
            :rtype: bytes
            """
            priv_key_size = self.priv_key_size
            priv_key = _ffi.new(f"unsigned char[{priv_key_size}]")
            out_len = _ffi.new("word32 *")
            out_len[0] = priv_key_size
            ret = _lib.wc_dilithium_export_private(
                self.native_object, priv_key, out_len
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_export_private() error (%d)" % ret)

            return _ffi.buffer(priv_key, out_len[0])[:]

        def encode_priv_key_der(self):
            """
            :return: exported private key in DER format
            :rtype: bytes
            """
            priv_key_size = self.priv_key_size
            # DER encoding adds some overhead
            der_size = priv_key_size + 50
            output = _ffi.new(f"unsigned char[{der_size}]")
            # Use export_private instead of PrivateKeyToDer since there's no direct equivalent
            out_len = _ffi.new("word32 *")
            out_len[0] = der_size
            ret = _lib.wc_dilithium_export_private(
                self.native_object, output, out_len
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_export_private() error (%d)" % ret)

            return _ffi.buffer(output, out_len[0])[:]

        def sign(self, message, rng=Random()):
            """
            :param message: message to be signed
            :type message: bytes or str
            :param rng: random number generator
            :type rng: Random
            :return: signature
            :rtype: bytes
            """
            message = t2b(message)
            sig_size = self.sig_size
            signature = _ffi.new(f"unsigned char[{sig_size}]")
            sig_len = _ffi.new("word32 *")
            sig_len[0] = sig_size

            ret = _lib.wc_dilithium_sign_msg(
                _ffi.from_buffer(message),
                len(message),
                signature,
                sig_len,
                self.native_object,
                rng.native_object
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_sign_msg() error (%d)" % ret)

            return _ffi.buffer(signature, sig_len[0])[:] 

    class MlDsaPublic(_MlDsaBase):
        def decode_key(self, pub_key):
            """
            :param pub_key: public key to be imported
            :type pub_key: bytes or str
            """
            pub_key_bytestype = t2b(pub_key)
            ret = _lib.wc_dilithium_import_public(
                _ffi.from_buffer(pub_key_bytestype),
                len(pub_key_bytestype),
                self.native_object
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_import_public() error (%d)" % ret)

        def encode_key(self):
            """
            :return: exported public key
            :rtype: bytes
            """
            return self._encode_pub_key()

        def encode_key_der(self, with_alg=1):
            """
            :return: exported public key in DER format
            :rtype: bytes
            """
            return self._encode_pub_key_der(with_alg)

        def verify(self, signature, message):
            """
            :param signature: signature to be verified
            :type signature: bytes or str
            :param message: message to be verified
            :type message: bytes or str
            :return: True if the signature is valid, False otherwise
            :rtype: bool
            """
            signature = t2b(signature)
            message = t2b(message)
            res = _ffi.new("int *")

            ret = _lib.wc_dilithium_verify_msg(
                _ffi.from_buffer(signature),
                len(signature),
                _ffi.from_buffer(message),
                len(message),
                res,
                self.native_object
            )

            if ret < 0:  # pragma: no cover
                raise WolfCryptError("wc_dilithium_verify_msg() error (%d)" % ret)

            return res[0] == 1
