# test_error_string.py
#
# Copyright (C) 2026 wolfSSL Inc.
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

import pytest

from wolfcrypt._ffi import lib as _lib
from wolfcrypt.exceptions import error_string


@pytest.mark.skipif(not _lib.ERROR_STRINGS_ENABLED, reason="wc_GetErrorString not enabled")
@pytest.mark.parametrize("err", (_lib.WC_FAILURE, _lib.KEY_EXHAUSTED_E, _lib.NO_PASSWORD, _lib.INTERRUPTED_E))
def test_error_string(err):
    # Error code 0 is an invalid error code (it means success)
    assert error_string(err) != error_string(0)
