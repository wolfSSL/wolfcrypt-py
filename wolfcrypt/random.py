# random.py
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

from _cffi_backend import FFI

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib

from wolfcrypt.exceptions import WolfCryptError


class Random:
    """
    A Cryptographically Secure Pseudo Random Number Generator - CSPRNG
    """

    def __init__(self, nonce=b"", device_id=_lib.INVALID_DEVID) -> None:
        self.native_object = _ffi.new("WC_RNG *")

        ret = _lib.wc_InitRngNonce_ex(self.native_object, nonce, len(nonce), _ffi.NULL, device_id)
        if ret < 0:  # pragma: no cover
            self.native_object = None
            raise WolfCryptError("RNG init error (%d)" % ret)

    # making sure _lib.wc_FreeRng outlives WC_RNG instances
    _delete = _lib.wc_FreeRng

    def __del__(self) -> None:
        if self.native_object:
            try:
                Random._delete(self.native_object)
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
            raise WolfCryptError("RNG generate byte error (%d)" % ret)

        return _ffi.buffer(result, 1)[:]

    def bytes(self, length) -> __builtins__.bytes:
        """
        Generate and return a random sequence of length bytes.
        """
        result = _ffi.new("byte[%d]" % length)

        assert self.native_object is not None
        ret = _lib.wc_RNG_GenerateBlock(self.native_object, result, length)
        if ret < 0:  # pragma: no cover
            raise WolfCryptError("RNG generate block error (%d)" % ret)

        return _ffi.buffer(result, length)[:]
