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

from wolfcrypt.exceptions import WolfCryptApiError


class Random:
    """
    A Cryptographically Secure Pseudo Random Number Generator - CSPRNG
    """

    def __init__(self, nonce: __builtins__.bytes = b"", device_id: int = -2) -> None:
        self.native_object: _lib.RNG | None = _ffi.new("WC_RNG *")

        ret = _lib.wc_InitRngNonce_ex(self.native_object, nonce, len(nonce), _ffi.NULL, device_id)
        if ret < 0:  # pragma: no cover
            self.native_object = None
            raise WolfCryptApiError("RNG init error", ret)

    # making sure _lib.wc_FreeRng outlives WC_RNG instances
    _delete = staticmethod(_lib.wc_FreeRng)

    def __del__(self) -> None:
        if self.native_object:
            try:
                self._delete(self.native_object)
            except AttributeError:
                # Can occur during interpreter shutdown
                pass

    def byte(self) -> __builtins__.bytes:
        """
        Generate and return a random byte.
        """
        result = _ffi.new("byte[1]")

        assert self.native_object is not None
        ret = _lib.wc_RNG_GenerateByte(self.native_object, result)
        if ret < 0:  # pragma: no cover
            raise WolfCryptApiError("RNG generate byte error", ret)

        return _ffi.buffer(result, 1)[:]

    def bytes(self, length: int) -> __builtins__.bytes:
        """
        Generate and return a random sequence of length bytes.
        """
        result = _ffi.new(f"byte[{length}]")

        assert self.native_object is not None
        ret = _lib.wc_RNG_GenerateBlock(self.native_object, result, length)
        if ret < 0:  # pragma: no cover
            raise WolfCryptApiError("RNG generate block error", ret)

        return _ffi.buffer(result, length)[:]
