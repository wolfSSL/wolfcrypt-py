# asn.py
#
# Copyright (C) 2006-2020 wolfSSL Inc.
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


if _lib.ASN_ENABLED:
    def pem_to_der(pem, pem_type):
        der = _ffi.new("DerBuffer**")
        ret = _lib.wc_PemToDer(pem, len(pem), pem_type, der, _ffi.NULL,
                               _ffi.NULL, _ffi.NULL)
        if ret != 0:
            err = "Error converting from PEM to DER. ({})".format(ret)
            raise WolfCryptError(err)

        return _ffi.buffer(der[0][0].buffer, der[0][0].length)[:]

    def der_to_pem(der, pem_type):
        pem_length = _lib.wc_DerToPemEx(der, len(der), _ffi.NULL, 0, _ffi.NULL,
                                        pem_type)
        if pem_length <= 0:
            err = "Error getting required PEM buffer length. ({})".format(pem_length)
            raise WolfCryptError(err)

        pem = _ffi.new("byte[%d]" % pem_length)
        pem_length = _lib.wc_DerToPemEx(der, len(der), pem, pem_length,
                                        _ffi.NULL, pem_type)
        if pem_length <= 0:
            err = "Error converting from DER to PEM. ({})".format(pem_length)
            raise WolfCryptError(err)

        return _ffi.buffer(pem, pem_length)[:]
