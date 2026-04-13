# test_aesgcmstream.py
#
# Copyright (C) 2022 wolfSSL Inc.
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

from wolfcrypt._ffi import lib as _lib

if _lib.AESGCM_STREAM_ENABLED:
    import pytest
    from wolfcrypt.utils import t2b
    from wolfcrypt.exceptions import WolfCryptError
    from binascii import hexlify as b2h
    from wolfcrypt.ciphers import AesGcmStream

    def test_encrypt():
        key = "fedcba9876543210"
        iv = "0123456789abcdef"
        gcm = AesGcmStream(key, iv)
        buf = gcm.encrypt("hello world")
        authTag = gcm.final()
        assert b2h(authTag) == bytes('ac8fcee96dc6ef8e5236da19b6197d2e', 'utf-8')
        assert b2h(buf) == bytes('5ba7d42e1bf01d7998e932', "utf-8")
        gcmdec = AesGcmStream(key, iv)
        bufdec = gcmdec.decrypt(buf)
        gcmdec.final(authTag)
        assert bufdec == t2b("hello world")

    def test_encrypt_short_tag():
        key = "fedcba9876543210"
        iv = "0123456789abcdef"
        gcm = AesGcmStream(key, iv, 12)
        buf = gcm.encrypt("hello world")
        authTag = gcm.final()
        assert b2h(authTag) == bytes('ac8fcee96dc6ef8e5236da19', 'utf-8')
        assert b2h(buf) == bytes('5ba7d42e1bf01d7998e932', "utf-8")
        gcmdec = AesGcmStream(key, iv)
        bufdec = gcmdec.decrypt(buf)
        gcmdec.final(authTag)
        assert bufdec == t2b("hello world")

    def test_multipart():
        key = "fedcba9876543210"
        iv = "0123456789abcdef"
        gcm = AesGcmStream(key, iv)
        buf = gcm.encrypt("hello")
        buf += gcm.encrypt(" world")
        authTag = gcm.final()
        assert b2h(authTag) == bytes('ac8fcee96dc6ef8e5236da19b6197d2e', 'utf-8')
        assert b2h(buf) == bytes('5ba7d42e1bf01d7998e932', "utf-8")
        gcmdec = AesGcmStream(key, iv)
        bufdec = gcmdec.decrypt(buf[:5])
        bufdec += gcmdec.decrypt(buf[5:])
        gcmdec.final(authTag)
        assert bufdec == t2b("hello world")

    def test_encrypt_aad():
        key = "fedcba9876543210"
        iv = "0123456789abcdef"
        aad = "aad data"
        gcm = AesGcmStream(key, iv)
        gcm.set_aad(aad)
        buf = gcm.encrypt("hello world")
        authTag = gcm.final()
        print(b2h(authTag))
        assert b2h(authTag) == bytes('8f85338aa0b13f48f8b17482dbb8acca', 'utf-8')
        assert b2h(buf) == bytes('5ba7d42e1bf01d7998e932', "utf-8")
        gcmdec = AesGcmStream(key, iv)
        gcmdec.set_aad(aad)
        bufdec = gcmdec.decrypt(buf)
        gcmdec.final(authTag)
        assert bufdec == t2b("hello world")

    def test_multipart_aad():
        key = "fedcba9876543210"
        iv = "0123456789abcdef"
        aad = "aad data"
        gcm = AesGcmStream(key, iv)
        gcm.set_aad(aad)
        buf = gcm.encrypt("hello")
        buf += gcm.encrypt(" world")
        authTag = gcm.final()
        assert b2h(authTag) == bytes('8f85338aa0b13f48f8b17482dbb8acca', 'utf-8')
        assert b2h(buf) == bytes('5ba7d42e1bf01d7998e932', "utf-8")
        gcmdec = AesGcmStream(key, iv)
        gcmdec.set_aad(aad)
        bufdec = gcmdec.decrypt(buf[:5])
        bufdec += gcmdec.decrypt(buf[5:])
        gcmdec.final(authTag)
        assert bufdec == t2b("hello world")

    def test_encrypt_aad_bad():
        key = "fedcba9876543210"
        iv = "0123456789abcdef"
        aad = "aad data"
        aad_bad = "bad data"
        gcm = AesGcmStream(key, iv)
        gcm.set_aad(aad)
        buf = gcm.encrypt("hello world")
        authTag = gcm.final()
        print(b2h(authTag))
        assert b2h(authTag) == bytes('8f85338aa0b13f48f8b17482dbb8acca', 'utf-8')
        assert b2h(buf) == bytes('5ba7d42e1bf01d7998e932', "utf-8")
        gcmdec = AesGcmStream(key, iv)
        gcmdec.set_aad(aad_bad)
        gcmdec.decrypt(buf)
        with pytest.raises(WolfCryptError):
            gcmdec.final(authTag)

    def test_invalid_tag_bytes():
        key = "fedcba9876543210"
        iv = "0123456789abcdef"
        # Out of range
        with pytest.raises(ValueError, match="tag_bytes must be one of"):
            AesGcmStream(key, iv, tag_bytes=0)
        with pytest.raises(ValueError, match="tag_bytes must be one of"):
            AesGcmStream(key, iv, tag_bytes=3)
        with pytest.raises(ValueError, match="tag_bytes must be one of"):
            AesGcmStream(key, iv, tag_bytes=17)
        # Non-NIST sizes within 4-16 range
        for bad in (5, 6, 7, 9, 10, 11):
            with pytest.raises(ValueError, match="tag_bytes must be one of"):
                AesGcmStream(key, iv, tag_bytes=bad)
        # Valid NIST sizes: verify the resulting tag has the requested length.
        for good in (4, 8, 12, 13, 14, 15, 16):
            gcm = AesGcmStream(key, iv, tag_bytes=good)
            gcm.encrypt("hello world")
            tag = gcm.final()
            assert len(tag) == good

    def test_repeated_construction_destruction():
        import gc
        key = "fedcba9876543210"
        iv = "0123456789abcdef"
        for _ in range(1000):
            gcm = AesGcmStream(key, iv)
            gcm.encrypt("hello world")
            gcm.final()
            del gcm
        gc.collect()
