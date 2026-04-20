# utils.py
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

# pylint: disable=unused-import

from __future__ import annotations

from binascii import hexlify as b2h, unhexlify as h2b  # noqa: F401


def t2b(string: bytes | bytearray | memoryview | str) -> bytes:
    """
    Converts text to bytes.

    Passes through bytes unchanged.
    Objects of type bytearray or memoryview are converted to bytes.
    Encodes str to UTF-8 bytes.

    :param string: text to convert to bytes.
    :raises TypeError: if string is not one of the supported types.
    """
    if isinstance(string, bytes):
        return string
    if isinstance(string, (bytearray, memoryview)):
        return bytes(string)
    if isinstance(string, str):
        return str(string).encode("utf-8")
    raise TypeError(f"String parameter of wrong type {type(string).__name__}, expected bytes, bytearray, memoryview or str")
