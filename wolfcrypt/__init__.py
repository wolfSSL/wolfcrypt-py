# __init__.py
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

from __future__ import annotations

import os
import sys

from wolfcrypt._version import __version__, __wolfssl_version__

__title__ = "wolfcrypt"
__summary__ = "Python module that encapsulates wolfSSL's crypto engine API."
__uri__ = "https://github.com/wolfssl/wolfcrypt-py"

__author__ = "wolfSSL Inc."
__email__ = "info@wolfssl.com"

__license__ = "GPLv3-or-later or Commercial License"
__copyright__ = "Copyright (C) 2006-2026 wolfSSL Inc"

__all__ = [
    "__title__", "__summary__", "__uri__", "__version__", "__wolfssl_version__",
    "__author__", "__email__", "__license__", "__copyright__",
    "ciphers", "hashes", "random", "pwdbased", "cryptocb"
]

top_level_py = os.path.basename(sys.argv[0])

# The code below is intended to only be used after the CFFI is built, so we
# don't want it invoked whilst building the CFFI with build_ffi.py or setup.py.
if top_level_py not in ["setup.py", "build_ffi.py"]:
    import logging
    from typing import TYPE_CHECKING
    from wolfcrypt._ffi import ffi as _ffi
    from wolfcrypt._ffi import lib as _lib

    if TYPE_CHECKING:
        if _lib.CRYPTO_CB_ENABLED:
            from types import TracebackType
            from wolfcrypt.cryptocb import CryptoCallback  # ty: ignore[possibly-missing-import]
    from wolfcrypt.exceptions import WolfCryptApiError

    log = logging.getLogger("wolfcrypt")

    # Only wolfCrypt_Init() is called here.
    # Calling wolfCrypt_Cleanup() is not needed as the application exit() will clean up the entire process
    # including any wolfcrypt data in any case.
    ret = _lib.wolfCrypt_Init()
    if ret < 0:
        raise WolfCryptApiError("WolfCrypt_Init failed", ret)

    if _lib.CRYPTO_CB_ENABLED:
        def crypto_cb_error_handler(exception: Exception, exc_value: Exception, traceback: TracebackType | None) -> int:  # noqa: ANN401
            if isinstance(exc_value, WolfCryptApiError):
                return exc_value.err_code
            log.error(exc_value)
            return -1

        @_ffi.def_extern(onerror=crypto_cb_error_handler)
        def py_wc_crypto_callback(device_id: int, info: _lib.wc_CryptoInfo, ctx: _ffi.CData) -> int:
            if ctx == _ffi.NULL:
                return _lib.CRYPTOCB_UNAVAILABLE
            crypto_cb: CryptoCallback = _ffi.from_handle(ctx)
            return crypto_cb.callback(device_id, info)

    if hasattr(_lib, 'WC_RNG_SEED_CB_ENABLED'):
        if _lib.WC_RNG_SEED_CB_ENABLED:
            ret = _lib.wc_SetSeed_Cb(_ffi.addressof(_lib, "wc_GenerateSeed"))  # ty: ignore[no-matching-overload]
            if ret < 0:
                raise WolfCryptApiError("wc_SetSeed_Cb failed", ret)
    if _lib.FIPS_ENABLED and _lib.FIPS_VERSION >= 5:
        ret = _lib.wolfCrypt_SetPrivateKeyReadEnable_fips(1, _lib.WC_KEYTYPE_ALL)
        if ret < 0:
            raise WolfCryptApiError("wolfCrypt_SetPrivateKeyReadEnable_fips failed", ret)
