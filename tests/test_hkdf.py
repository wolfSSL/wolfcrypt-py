# test_hkdf.py
#
# Copyright (C) 2025 wolfSSL Inc.
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

import pytest

from wolfcrypt._ffi import lib as _lib
from wolfcrypt.hkdf import HKDF, HKDF_Extract, HKDF_Expand
from wolfcrypt.hashes import HmacSha, HmacSha256

# Skip the whole module if required features are not available.
pytestmark = pytest.mark.skipif(
    not (_lib.HKDF_ENABLED and _lib.SHA256_ENABLED and _lib.HMAC_ENABLED),
    reason="HKDF/SHA256/HMAC not enabled in the underlying wolfCrypt library",
)


def test_hkdf_rfc5869_case1_full():
    """
    RFC 5869 Test Case 1 (SHA-256).
    """
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42

    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    okm = HKDF(HmacSha256, ikm, salt=salt, info=info, out_len=length)
    assert isinstance(okm, bytes)
    assert len(okm) == length
    assert okm == expected_okm


def test_hkdf_rfc5869_case1_split_extract_expand():
    """
    Same vector as above but exercised via HKDF_Extract and HKDF_Expand.
    Verifies the PRK (pseudorandom key) and the final OKM.
    """
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42

    expected_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    prk = HKDF_Extract(HmacSha256, salt, ikm)
    assert isinstance(prk, bytes)
    assert prk == expected_prk

    okm = HKDF_Expand(HmacSha256, prk, info, length)
    assert isinstance(okm, bytes)
    assert len(okm) == length
    assert okm == expected_okm


def test_hkdf_rfc5869_case2_full_and_split():
    """
    RFC 5869 Test Case 2 (SHA-256) - longer inputs/outputs
    """
    ikm = bytes(range(0x00, 0x00 + 80))
    salt = bytes(range(0x60, 0x60 + 80))
    info = bytes(range(0xB0, 0xB0 + 80))
    length = 82

    expected_prk = bytes.fromhex(
        "06a6b88c5853361a06104c9ceb35b45c"
        "ef760014904671014a193f40c15fc244"
    )
    expected_okm = bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87"
    )

    # Full
    okm = HKDF(HmacSha256, ikm, salt=salt, info=info, out_len=length)
    assert isinstance(okm, bytes)
    assert len(okm) == length
    assert okm == expected_okm

    # Split: check PRK then expand
    prk = HKDF_Extract(HmacSha256, salt, ikm)
    assert prk == expected_prk

    okm2 = HKDF_Expand(HmacSha256, prk, info, length)
    assert okm2 == expected_okm


def test_hkdf_rfc5869_case3_full_and_split():
    """
    RFC 5869 Test Case 3 (SHA-256) - zero-length salt/info
    """
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = b""
    info = b""
    length = 42

    expected_prk = bytes.fromhex(
        "19ef24a32c717b167f33a91d6f648bdf"
        "96596776afdb6377ac434c1c293ccb04"
    )
    expected_okm = bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )

    okm = HKDF(HmacSha256, ikm, salt=salt, info=info, out_len=length)
    assert okm == expected_okm

    prk = HKDF_Extract(HmacSha256, salt, ikm)
    assert prk == expected_prk

    okm2 = HKDF_Expand(HmacSha256, prk, info, length)
    assert okm2 == expected_okm


def test_hkdf_rfc5869_case4_sha1_full_and_split():
    """
    RFC 5869 Test Case 4 (SHA-1) - basic test
    """
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42

    expected_prk = bytes.fromhex("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243")
    expected_okm = bytes.fromhex(
        "085a01ea1b10f36933068b56efa5ad81"
        "a4f14b822f5b091568a9cdd4f155fda2"
        "c22e422478d305f3f896"
    )

    okm = HKDF(HmacSha, ikm, salt=salt, info=info, out_len=length)
    assert okm == expected_okm

    prk = HKDF_Extract(HmacSha, salt, ikm)
    assert prk == expected_prk

    okm2 = HKDF_Expand(HmacSha, prk, info, length)
    assert okm2 == expected_okm


def test_hkdf_rfc5869_case5_sha1_long_full_and_split():
    """
    RFC 5869 Test Case 5 (SHA-1) - longer inputs/outputs
    """
    ikm = bytes(range(0x00, 0x00 + 80))
    salt = bytes(range(0x60, 0x60 + 80))
    info = bytes(range(0xB0, 0xB0 + 80))
    length = 82

    expected_prk = bytes.fromhex("8adae09a2a307059478d309b26c4115a224cfaf6")
    expected_okm = bytes.fromhex(
        "0bd770a74d1160f7c9f12cd5912a06eb"
        "ff6adcae899d92191fe4305673ba2ffe"
        "8fa3f1a4e5ad79f3f334b3b202b2173c"
        "486ea37ce3d397ed034c7f9dfeb15c5e"
        "927336d0441f4c4300e2cff0d0900b52"
        "d3b4"
    )

    okm = HKDF(HmacSha, ikm, salt=salt, info=info, out_len=length)
    assert okm == expected_okm

    prk = HKDF_Extract(HmacSha, salt, ikm)
    assert prk == expected_prk

    okm2 = HKDF_Expand(HmacSha, prk, info, length)
    assert okm2 == expected_okm


def test_hkdf_rfc5869_case6_sha1_zero_salt_info():
    """
    RFC 5869 Test Case 6 (SHA-1) - zero-length salt/info
    """
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = b""
    info = b""
    length = 42

    expected_prk = bytes.fromhex("da8c8a73c7fa77288ec6f5e7c297786aa0d32d01")
    expected_okm = bytes.fromhex(
        "0ac1af7002b3d761d1e55298da9d0506"
        "b9ae52057220a306e07b6b87e8df21d0"
        "ea00033de03984d34918"
    )

    prk = HKDF_Extract(HmacSha, salt, ikm)
    assert prk == expected_prk

    okm = HKDF(HmacSha, ikm, salt=salt, info=info, out_len=length)
    assert okm == expected_okm

    okm2 = HKDF_Expand(HmacSha, prk, info, length)
    assert okm2 == expected_okm


def test_hkdf_rfc5869_case7_sha1_salt_not_provided():
    """
    RFC 5869 Test Case 7 (SHA-1) - salt not provided (defaults to zeros),
    zero-length info.
    """
    ikm = bytes.fromhex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
    info = b""
    length = 42

    expected_prk = bytes.fromhex("2adccada18779e7c2077ad2eb19d3f3e731385dd")
    expected_okm = bytes.fromhex(
        "2c91117204d745f3500d636a62f64f0a"
        "b3bae548aa53d423b0d1f27ebba6f5e5"
        "673a081d70cce7acfc48"
    )

    # For Extract: when salt is not provided, pass b"" (wc_HKDF_Extract treats
    # empty salt as zeros).
    # Some implementations treat "not provided" as explicit None;
    # wc_HKDF_Extract expects salt pointer and length, so passing empty salt
    # (length 0) is equivalent to RFC specification (salt = HashLen zeros).
    prk = HKDF_Extract(HmacSha, None, ikm)
    assert prk == expected_prk

    okm = HKDF(HmacSha, ikm, salt=None, info=info, out_len=length)
    assert okm == expected_okm

    okm2 = HKDF_Expand(HmacSha, prk, info, length)
    assert okm2 == expected_okm
