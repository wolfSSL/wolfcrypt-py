# random.py
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

# pylint: disable=no-member,no-name-in-module

from __future__ import annotations

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib

from wolfcrypt.exceptions import WolfCryptApiError, WolfCryptError


class Random:
    """
    A Cryptographically Secure Pseudo Random Number Generator - CSPRNG
    """

    def __init__(self, nonce: __builtins__.bytes = b"", device_id: int = _lib.INVALID_DEVID) -> None:
        self._native_object: _lib.RNG | None = None
        self._native_object = _ffi.new("WC_RNG *")

        ret = _lib.wc_InitRngNonce_ex(self._native_object, nonce, len(nonce), _ffi.NULL, device_id)
        if ret < 0:  # pragma: no cover
            self._native_object = None
            raise WolfCryptApiError("RNG init error", ret)

    # making sure _lib.wc_FreeRng outlives WC_RNG instances
    _delete = staticmethod(_lib.wc_FreeRng)

    def __del__(self) -> None:
        if self._native_object is not None:
            try:
                self._delete(self._native_object)
            except AttributeError:
                # Can occur during interpreter shutdown
                pass

    @property
    def native_object(self) -> _lib.RNG:
        if self._native_object is None:
            raise WolfCryptError("RNG not initialized")
        return self._native_object

    def byte(self) -> __builtins__.bytes:
        """
        Generate and return a random byte.
        """
        result = _ffi.new("byte[1]")

        ret = _lib.wc_RNG_GenerateByte(self.native_object, result)
        if ret < 0:  # pragma: no cover
            raise WolfCryptApiError("RNG generate byte error", ret)

        return _ffi.buffer(result, 1)[:]

    def bytes(self, length: int) -> __builtins__.bytes:
        """
        Generate and return a random sequence of length bytes.
        """
        result = _ffi.new(f"byte[{length}]")

        ret = _lib.wc_RNG_GenerateBlock(self.native_object, result, length)
        if ret < 0:  # pragma: no cover
            raise WolfCryptApiError("RNG generate block error", ret)

        return _ffi.buffer(result, length)[:]

    if _lib.HASHDRBG_ENABLED:
        def reseed(self, seed: __builtins__.bytes) -> None:
            """
            Reseed the DRBG with the provided seed material.
            """
            assert self.native_object is not None
            ret = _lib.wc_RNG_DRBG_Reseed(self.native_object, seed, len(seed))
            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("RNG reseed error", ret)
