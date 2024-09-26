
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

if _lib.CHACHA20_POLY1305_ENABLED:
    from collections import namedtuple
    import pytest
    from wolfcrypt.utils import t2b
    from wolfcrypt.exceptions import WolfCryptError
    from binascii import hexlify as b2h, unhexlify as h2b
    from wolfcrypt.ciphers import ChaCha20Poly1305

    def test_encrypt_decrypt():
        key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        key = h2b(key)
        iv = "07000000404142434445464748" #Chnage from C test
        iv = h2b(iv)
        aad = "50515253c0c1c2c3c4c5c6c7" #Change from C test
        aad = h2b(aad)
        plaintext1 = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
        plaintext1 = h2b(plaintext1)
        cipher1 = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        authTag = "1ae10b594f09e26a7e902ecbd0600691"
        chacha = ChaCha20Poly1305(key, iv, aad)
        generatedChipherText, generatedAuthTag = chacha.encrypt(plaintext1)
        assert h2b(cipher1) == generatedChipherText
        assert h2b(authTag) == generatedAuthTag
        chachadec = ChaCha20Poly1305(key, iv, aad)
        generatedPlaintextdec = chachadec.decrypt(generatedAuthTag, generatedChipherText)#takes in the generated authtag made by encrypt and decrypts and produces the plaintext
        assert generatedPlaintextdec == t2b("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
