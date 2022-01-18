# pwdbased.py
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

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib

from wolfcrypt.exceptions import WolfCryptError

if _lib.PWDBASED_ENABLED:
    def PBKDF2(password, salt, iterations, key_length, hash_type):
        if isinstance(salt, str):
            salt = str.encode(salt)

        if isinstance(password, str):
            password = str.encode(password)

        key = _ffi.new("byte[%d]" %key_length)
        ret = _lib.wc_PBKDF2(key, password, len(password), salt, len(salt),
                             iterations, key_length, hash_type)

        if ret != 0:
            raise WolfCryptError("PBKDF2 error (%d)" % ret)

        return _ffi.buffer(key, key_length)[:]
