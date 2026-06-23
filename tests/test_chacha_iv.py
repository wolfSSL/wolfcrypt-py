# -*- coding: utf-8 -*-
#
# test_chacha_iv.py
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
from wolfcrypt.exceptions import WolfCryptError

pytestmark = pytest.mark.skipif(
    not _lib.CHACHA_ENABLED, reason="ChaCha not enabled")

KEY = b"\x01" * 32
NONCE = b"\x02" * 12


def test_encrypt_before_set_iv_raises():
    """
    F-4463: encrypt() before set_iv() must not feed an empty IV buffer to
    wc_Chacha_SetIV (which unconditionally reads 12 bytes). It must raise.
    """
    from wolfcrypt.ciphers import ChaCha

    cipher = ChaCha(KEY)
    with pytest.raises(WolfCryptError):
        cipher.encrypt(b"A" * 16)


def test_decrypt_before_set_iv_raises():
    from wolfcrypt.ciphers import ChaCha

    cipher = ChaCha(KEY)
    with pytest.raises(WolfCryptError):
        cipher.decrypt(b"A" * 16)


def test_encrypt_decrypt_after_set_iv_roundtrips():
    from wolfcrypt.ciphers import ChaCha

    enc = ChaCha(KEY)
    enc.set_iv(NONCE)
    plaintext = b"the quick brown fox"
    ciphertext = enc.encrypt(plaintext)

    dec = ChaCha(KEY)
    dec.set_iv(NONCE)
    assert dec.decrypt(ciphertext) == plaintext
