# asn.py
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

# pylint: disable=no-member,no-name-in-module

from __future__ import annotations

import hmac as _hmac

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.exceptions import WolfCryptError, WolfCryptApiError
from wolfcrypt.hashes import _Hash

if _lib.SHA_ENABLED:
    from wolfcrypt.hashes import Sha  # ty: ignore[possibly-missing-import]
if _lib.SHA256_ENABLED:
    from wolfcrypt.hashes import Sha256  # ty: ignore[possibly-missing-import]
if _lib.SHA384_ENABLED:
    from wolfcrypt.hashes import Sha384  # ty: ignore[possibly-missing-import]
if _lib.SHA512_ENABLED:
    from wolfcrypt.hashes import Sha512  # ty: ignore[possibly-missing-import]

if _lib.ASN_ENABLED:
    def pem_to_der(pem: bytes, pem_type: int) -> bytes:
        der = _ffi.new("DerBuffer**")
        ret = _lib.wc_PemToDer(pem, len(pem), pem_type, der, _ffi.NULL,
                               _ffi.NULL, _ffi.NULL)
        if ret != 0:
            raise WolfCryptApiError("Error converting from PEM to DER.", ret)

        try:
            result = _ffi.buffer(der[0][0].buffer, der[0][0].length)[:]
        finally:
            _lib.wc_FreeDer(der)
        return result

    def der_to_pem(der: bytes, pem_type: int) -> bytes:
        pem_length = _lib.wc_DerToPemEx(der, len(der), _ffi.NULL, 0, _ffi.NULL,
                                        pem_type)
        if pem_length <= 0:
            raise WolfCryptApiError("Error getting required PEM buffer length.", pem_length)

        pem = _ffi.new(f"byte[{pem_length}]")
        pem_length = _lib.wc_DerToPemEx(der, len(der), pem, pem_length,
                                        _ffi.NULL, pem_type)
        if pem_length <= 0:
            raise WolfCryptApiError("Error converting from DER to PEM.", pem_length)

        return _ffi.buffer(pem, pem_length)[:]

    def hash_oid_from_class(hash_cls: type[_Hash]) -> int:
        if _lib.SHA_ENABLED and hash_cls == Sha:
            return _lib.SHAh
        elif _lib.SHA256_ENABLED and hash_cls == Sha256:
            return _lib.SHA256h
        elif _lib.SHA384_ENABLED and hash_cls == Sha384:
            return _lib.SHA384h
        elif _lib.SHA512_ENABLED and hash_cls == Sha512:
            return _lib.SHA512h
        else:
            raise WolfCryptError(f"Unknown hash class {hash_cls.__name__}")

    def make_signature(data: bytes, hash_cls: type[_Hash], key = None) -> bytes:
        hash_obj = hash_cls()
        hash_obj.update(data)
        digest = hash_obj.digest()

        plaintext_sig = _ffi.new(f"byte[{_lib.MAX_DER_DIGEST_SZ}]")
        hash_oid = hash_oid_from_class(hash_cls)
        plaintext_len = _lib.wc_EncodeSignature(plaintext_sig, digest,
                                                len(digest), hash_oid)
        if plaintext_len == 0:
            raise WolfCryptError(f"Error calling wc_EncodeSignature. ({plaintext_len})")

        plaintext_sig = _ffi.buffer(plaintext_sig, plaintext_len)[:]
        if key:
            return key.sign(plaintext_sig)
        else:
            return plaintext_sig

    def check_signature(signature: bytes, data: bytes, hash_cls: type[_Hash], pub_key) -> bool:
        computed_signature = make_signature(data, hash_cls)
        decrypted_signature = pub_key.verify(signature)
        return _hmac.compare_digest(computed_signature, decrypted_signature)
