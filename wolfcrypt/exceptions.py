# exceptions.py
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


from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib


class WolfCryptError(Exception):
    pass


class WolfCryptApiError(WolfCryptError):
    """
    WolfCrypt API error displaying the error code and error message if support is compiled in.
    """
    def __init__(self, message: str, err_code: int) -> None:
        """
        Create a WolfCryptApiError exception.

        :param message: error message
        :param err_code: WolfCrypt error code
        """
        err_string = error_string(err_code)

        if err_string:
            reason = f": {err_string}"
        else:
            reason = ""

        super().__init__(f"{message} ({err_code}){reason}")


def error_string(err_code: int) -> str:
    """
    Convert error code to error string.

    :param err_code: WolfCrypt error code
    :return: error string
    """
    if _lib.ERROR_STRINGS_ENABLED:
        return _ffi.string(_lib.wc_GetErrorString(err_code)).decode()
    else:
        return ""
