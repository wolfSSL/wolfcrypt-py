# buidl_ciphers.py
#
# Copyright (C) 2006-2016 wolfSSL Inc.
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
import os

from cffi import FFI

ffi = FFI()

ffi.set_source("wolfcrypt._ciphers",
    """
        #include <wolfssl/options.h>
        #include <wolfssl/wolfcrypt/des3.h>
    """,
    include_dirs=["/usr/local/include"],
    library_dirs=["/usr/local/lib"],
    libraries=["wolfssl"],
)

ffi.cdef(
"""

    typedef unsigned char byte;
    typedef unsigned int  word32;

    typedef struct { ...; } Des3;

    int wc_Des3_SetKey(Des3* des, const byte* key, const byte* iv,int dir);
    int wc_Des3_CbcEncrypt(Des3* des, byte* out, const byte* in,word32 sz);
    int wc_Des3_CbcDecrypt(Des3* des, byte* out, const byte* in,word32 sz);

"""
)

if __name__ == "__main__":
    ffi.compile(verbose=1)
