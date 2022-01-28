# test_hashes.py
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

# pylint: disable=redefined-outer-name

from collections import namedtuple
import pytest
from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.utils import t2b
from binascii import hexlify as b2h, unhexlify as h2b

from wolfcrypt.ciphers import AesGcmStreamEncrypt, AesGcmStreamDecrypt

def test_encrypt():
    key = "fedcba9876543210"
    iv = "0123456789abcdef"
    gcm = AesGcmStreamEncrypt(key, iv)
    buf = gcm.update("hello world")
    authTag = gcm.final()
    assert b2h(authTag) == bytes('cef91ba0c8c6431c7e19f64c9d9e371b', 'utf-8')
    assert b2h(buf) == bytes('5ba7d42e1bf01d7998e932', "utf-8")
    gcmdec = AesGcmStreamDecrypt(key, iv)
    bufdec = gcmdec.update(buf)
    gcmdec.final(authTag)
    assert bufdec == t2b("hello world")

def test_multipart():
    key = "fedcba9876543210"
    iv = "0123456789abcdef"
    gcm = AesGcmStreamEncrypt(key, iv)
    buf = gcm.update("hello")
    buf += gcm.update(" world")
    authTag = gcm.final()
    assert b2h(authTag) == bytes('6862647a27c7b6aa0a6882b3e117e944', 'utf-8')
    assert b2h(buf) == bytes('5ba7d42e1bf01d7998e932', "utf-8")
    gcmdec = AesGcmStreamDecrypt(key, iv)
    bufdec = gcmdec.update(buf[:5])
    bufdec += gcmdec.update(buf[5:])
    gcmdec.final(authTag)
    assert bufdec == t2b("hello world")
