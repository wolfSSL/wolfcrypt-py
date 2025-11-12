# hkdf.py
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

# pylint: disable=no-member,no-name-in-module

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib

from wolfcrypt.exceptions import WolfCryptError
from wolfcrypt.utils import t2b


if _lib.HKDF_ENABLED:

    def HKDF(hash_cls, in_key, salt=None, info=None, out_len=None):
        """
        Perform HKDF Extract-and-Expand in one call (wraps wc_HKDF).

        Parameters:
        - hash_cls: hash class, see `wolfcrypt.hashes`.
        - in_key: input key material (IKM) as bytes or str.
        - salt: optional salt value (bytes or str). If None, treated as empty.
        - info: optional context/application info (bytes or str). If None,
                treated as empty.
        - out_len: desired length of output keying material (bytes). If None,
                   defaults to the digest size of the hash.

        Returns:
        - bytes object containing the derived key of length `out_len`.

        Raises:
        - WolfCryptError on failure.
        - ValueError for invalid arguments.
        """
        in_key = t2b(in_key)
        salt = b"" if salt is None else t2b(salt)
        info = b"" if info is None else t2b(info)

        if out_len is None:
            out_len = hash_cls.digest_size

        out = _ffi.new("byte[%d]" % out_len)
        ret = _lib.wc_HKDF(
            hash_cls._type,
            in_key,
            len(in_key),
            salt,
            len(salt),
            info,
            len(info),
            out,
            out_len,
        )
        if ret != 0:
            raise WolfCryptError("HKDF error (%d)" % ret)

        return _ffi.buffer(out, out_len)[:]

    def HKDF_Extract(hash_cls, salt, in_key):
        """
        HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
        Wraps wc_HKDF_Extract.

        Parameters:
        - hash_cls: hash class, see `wolfcrypt.hashes`.
        - salt: bytes/str (can be None -> treated as empty).
        - in_key: input key material (IKM) as bytes/str.

        Returns:
        - PRK as bytes (length == hash digest size).

        Raises WolfCryptError on failure.
        """
        salt = b"" if salt is None else t2b(salt)
        in_key = t2b(in_key)

        out_len = hash_cls.digest_size
        out = _ffi.new("byte[%d]" % out_len)

        ret = _lib.wc_HKDF_Extract(hash_cls._type, salt, len(salt), in_key, len(in_key), out)
        if ret != 0:
            raise WolfCryptError("HKDF_Extract error (%d)" % ret)

        return _ffi.buffer(out, out_len)[:]

    def HKDF_Expand(hash_cls, prk, info, out_len):
        """
        HKDF-Expand: OKM = HKDF-Expand(PRK, info, L)
        Wraps wc_HKDF_Expand.

        Parameters:
        - hash_cls: hash class, see `wolfcrypt.hashes`.
        - prk: pseudorandom key (output from HKDF-Extract) as bytes/str.
        - info: optional context/application info (bytes/str). If None, treated as empty.
        - out_len: length of output keying material in bytes.

        Returns:
        - OKM as bytes of length `out_len`.

        Raises WolfCryptError on failure.
        """
        prk = t2b(prk)
        info = b"" if info is None else t2b(info)

        if out_len is None or out_len <= 0:
            raise ValueError("out_len must be a positive integer")

        out = _ffi.new("byte[%d]" % out_len)

        ret = _lib.wc_HKDF_Expand(
            hash_cls._type, prk, len(prk), info, len(info), out, out_len
        )
        if ret != 0:
            raise WolfCryptError("HKDF_Expand error (%d)" % ret)

        return _ffi.buffer(out, out_len)[:]
