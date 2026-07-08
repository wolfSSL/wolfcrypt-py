# test_cipher_modes.py
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

# pylint: disable=missing-docstring, import-error, protected-access

import pytest
from wolfcrypt.ciphers import (
    _FEEDBACK_MODES,
    MODE_CBC, MODE_CTR, MODE_ECB, MODE_CFB, MODE_OFB,
)
from wolfcrypt._ffi import lib as _lib


def test_feedback_modes_only_advertises_supported():
    """
    F-4015: _FEEDBACK_MODES is used as the "supported modes" gate in
    _Cipher.__init__. It must not advertise modes that the constructor
    then turns around and rejects.
    """
    assert MODE_CBC in _FEEDBACK_MODES
    assert MODE_CTR in _FEEDBACK_MODES
    for unsupported in (MODE_ECB, MODE_CFB, MODE_OFB):
        assert unsupported not in _FEEDBACK_MODES


@pytest.mark.skipif(not _lib.AES_ENABLED, reason="AES not enabled")
def test_unsupported_mode_gives_single_consistent_error():
    """
    F-4015: previously MODE_ECB passed the first "is supported" check and
    then hit a contradictory "not supported by this cipher" branch. The
    rejection must now be a single, consistent message.
    """
    from wolfcrypt.ciphers import Aes  # ty: ignore[possibly-missing-import]

    key = b"0" * 16
    iv = b"0" * 16
    with pytest.raises(ValueError) as exc_info:
        Aes.new(key, MODE_ECB, iv)

    assert "by this cipher" not in str(exc_info.value)
