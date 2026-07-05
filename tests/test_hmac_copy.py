# test_hmac_copy.py
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

# pylint: disable=missing-docstring, import-error

import pytest
from wolfcrypt._ffi import lib as _lib

pytestmark = pytest.mark.skipif(
    not (_lib.HMAC_ENABLED and _lib.SHA256_ENABLED),
    reason="HMAC-SHA256 not enabled")

KEY = b"wolfCrypt is the best crypto around"


def test_hmac_copy_raises_not_implemented():
    """
    F-5428: _Hmac inherited _Hash.copy(), which for HMAC fell back to a
    byte-level memmove and returned an object aliasing the original's C
    state (use-after-free risk in async/HW builds). wolfCrypt has no safe
    public copy, so HMAC copy() must refuse rather than alias.
    """
    from wolfcrypt.hashes import HmacSha256

    hmac = HmacSha256.new(KEY, b"some message")
    with pytest.raises(NotImplementedError):
        hmac.copy()


def test_hmac_digest_unaffected_by_copy_removal():
    """digest()/hexdigest() must keep working and remain repeatable."""
    from wolfcrypt.hashes import HmacSha256

    hmac = HmacSha256.new(KEY, b"some message")
    first = hmac.hexdigest()
    second = hmac.hexdigest()
    assert first == second

    hmac.update(b" more")
    assert hmac.hexdigest() != first
