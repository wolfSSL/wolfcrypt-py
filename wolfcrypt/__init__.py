# __init__.py
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

from wolfcrypt._version import __version__, __wolfssl_version__

__title__ = "wolfcrypt"
__summary__ = "Python module that encapsulates wolfSSL's crypto engine API."
__uri__ = "https://github.com/wolfssl/wolfcrypt-py"

__author__ = "wolfSSL Inc."
__email__ = "info@wolfssl.com"

__license__ = "GPLv2 or Commercial License"
__copyright__ = "Copyright (C) 2006-2022 wolfSSL Inc"

__all__ = [
    "__title__", "__summary__", "__uri__", "__version__",
    "__author__", "__email__", "__license__", "__copyright__",
    "ciphers", "hashes", "random", "pwdbased"
]

try:
    from wolfcrypt._ffi import ffi as _ffi
    from wolfcrypt._ffi import lib as _lib
except ImportError:
    # FFI not built. Not running initialization code.
    pass
else:
    from wolfcrypt.exceptions import WolfCryptError

    if hasattr(_lib, 'WC_RNG_SEED_CB_ENABLED'):
        if _lib.WC_RNG_SEED_CB_ENABLED:
            ret = _lib.wc_SetSeed_Cb(_ffi.addressof(_lib, "wc_GenerateSeed"))
            if ret < 0:
                raise WolfCryptError("wc_SetSeed_Cb failed (%d)" % ret)
    if _lib.FIPS_ENABLED and (_lib.FIPS_VERSION > 5 or (_lib.FIPS_VERSION == 5
        and _lib.FIPS_VERSION >= 1)):
        ret = _lib.wolfCrypt_SetPrivateKeyReadEnable_fips(1,
                                                          _lib.WC_KEYTYPE_ALL);
        if ret < 0:
            raise WolfCryptError("wolfCrypt_SetPrivateKeyReadEnable_fips failed"
                " (%d)" % ret)
