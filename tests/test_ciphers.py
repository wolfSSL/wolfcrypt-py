# test_ciphers.py
#
# Copyright (C) 2006-2018 wolfSSL Inc.
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
from wolfcrypt.utils import t2b, h2b
from wolfcrypt.ciphers import (
    Aes, Des3, MODE_ECB, MODE_CBC, RsaPrivate, RsaPublic,
    EccPrivate, EccPublic, WolfCryptError
)


@pytest.fixture
def vectors():
    TestVector = namedtuple("TestVector", "key iv plaintext ciphertext")
    TestVector.__new__.__defaults__ = (None,) * len(TestVector._fields)

    return {
        Aes: TestVector(
            key="0123456789abcdef",
            iv="1234567890abcdef",
            plaintext=t2b("now is the time "),
            ciphertext=h2b("959492575f4281532ccc9d4677a233cb")
        ),
        Des3: TestVector(
            key=h2b("0123456789abcdeffedeba987654321089abcdef01234567"),
            iv=h2b("1234567890abcdef"),
            plaintext=t2b("Now is the time for all "),
            ciphertext=h2b("43a0297ed184f80e8964843212d508981894157487127db0")
        ),
        RsaPublic: TestVector(
            key=h2b(
                "30819F300D06092A864886F70D010101050003818D0030818902818100BC"
                "730EA849F374A2A9EF18A5DA559921F9C8ECB36D48E53535757737ECD161"
                "905F3ED9E4D5DF94CAC1A9D719DA86C9E84DC4613682FEABAD7E7725BB8D"
                "11A5BC623AA838CC39A20466B4F7F7F3AADA4D020EBB5E8D6948DC77C928"
                "0E22E96BA426BA4CE8C1FD4A6F2B1FEF8AAEF69062E5641EEB2B3C67C8DC"
                "2700F6916865A90203010001")
        ),
        RsaPrivate: TestVector(
            key=h2b(
                "3082025C02010002818100BC730EA849F374A2A9EF18A5DA559921F9C8EC"
                "B36D48E53535757737ECD161905F3ED9E4D5DF94CAC1A9D719DA86C9E84D"
                "C4613682FEABAD7E7725BB8D11A5BC623AA838CC39A20466B4F7F7F3AADA"
                "4D020EBB5E8D6948DC77C9280E22E96BA426BA4CE8C1FD4A6F2B1FEF8AAE"
                "F69062E5641EEB2B3C67C8DC2700F6916865A902030100010281801397EA"
                "E8387825A25C04CE0D407C31E5C470CD9B823B5809863B665FDC3190F14F"
                "D5DB15DDDED73B95933118310E5EA3D6A21A716E81481C4BCFDB8E7A8661"
                "32DCFB55C1166D279224458BF1B848B14B1DACDEDADD8E2FC291FBA5A96E"
                "F83A6AF1FD5018EF9FE7C3CA78EA56D3D3725B96DD4E064E3AC3D9BE72B6"
                "6507074C01024100FA47D47A7C923C55EF81F041302DA3CF8F1CE6872705"
                "700DDF9835D6F18B382F24B5D084B6794F7129945AF0646AACE772C6ED4D"
                "59983E673AF3742CF9611769024100C0C1820D0CEBC62FDC92F99D821A31"
                "E9E9F74BF282871CEE166AD11D188270F3C0B62FF6F3F71DF18623C84EEB"
                "8F568E8FF5BFF1F72BB5CC3DC657390C1B54410241009D7E05DEEDF4B7B2"
                "FBFC304B551DE32F0147966905CD0E2E2CBD8363B6AB7CB76DCA5B64A7CE"
                "BE86DF3B53DE61D21EEBA5F637EDACAB78D94CE755FBD71199C102401898"
                "1829E61E2739702168AC0A2FA172C121869538C65890A0579CBAE3A7B115"
                "C8DEF61BC2612376EFB09D1C44BE1343396717C89DCAFBF545648B38822C"
                "F28102403989E59C195530BAB7488C48140EF49F7E779743E1B419353123"
                "759C3B44AD691256EE0061641666D37C742B15B4A2FEBF086B1A5D3F9012"
                "B105863129DBD9E2")
        ),
        EccPublic: TestVector(
            key=h2b(
                "3059301306072A8648CE3D020106082A8648CE3D0301070342000455BFF4"
                "0F44509A3DCE9BB7F0C54DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                "EFA2351243847616C6569506CC01A9BDF6751A42F7BDA9B236225FC75D7F"
                "B4"
            )
        ),
        EccPrivate: TestVector(
            key=h2b(
                "30770201010420F8CF926BBD1E28F1A8ABA1234F3274188850AD7EC7EC92"
                "F88F974DAF568965C7A00A06082A8648CE3D030107A1440342000455BFF4"
                "0F44509A3DCE9BB7F0C54DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                "EFA2351243847616C6569506CC01A9BDF6751A42F7BDA9B236225FC75D7F"
                "B4"
            )
        )
    }


@pytest.fixture(params=[Aes, Des3])
def cipher_cls(request):
    return request.param


def cipher_new(cipher_cls, vectors):
    return cipher_cls.new(
        vectors[cipher_cls].key,
        MODE_CBC,
        vectors[cipher_cls].iv)


def test_block_cipher(cipher_cls, vectors):
    key = vectors[cipher_cls].key
    iv = vectors[cipher_cls].iv
    plaintext = vectors[cipher_cls].plaintext
    ciphertext = vectors[cipher_cls].ciphertext

    with pytest.raises(ValueError):
        cipher_cls.new(key[:-1], MODE_CBC, iv)  # invalid key length

    with pytest.raises(ValueError):
        cipher_cls.new(key, -1, iv)             # invalid mode

    with pytest.raises(ValueError):
        cipher_cls.new(key, MODE_ECB, iv)       # unsuported mode

    with pytest.raises(ValueError):
        cipher_cls.new(key, MODE_CBC, None)     # invalid iv

    with pytest.raises(ValueError):
        cipher_cls.new(key, MODE_CBC, iv[:-1])  # invalid iv length

    # single encryption
    cipher_obj = cipher_new(cipher_cls, vectors)

    assert cipher_obj.encrypt(plaintext) == ciphertext

    # many encryptions
    cipher_obj = cipher_new(cipher_cls, vectors)
    result = t2b("")

    segments = tuple(plaintext[i:i + cipher_obj.block_size]
                     for i in range(0, len(plaintext), cipher_obj.block_size))

    for segment in segments:
        result += cipher_obj.encrypt(segment)

    assert result == ciphertext

    # single decryption
    cipher_obj = cipher_new(cipher_cls, vectors)

    assert cipher_obj.decrypt(ciphertext) == plaintext

    # many decryptions
    cipher_obj = cipher_new(cipher_cls, vectors)
    result = t2b("")

    segments = tuple(ciphertext[i:i + cipher_obj.block_size]
                     for i in range(0, len(ciphertext), cipher_obj.block_size))

    for segment in segments:
        result += cipher_obj.decrypt(segment)

    assert result == plaintext

    # invalid data sizes
    with pytest.raises(ValueError):
        cipher_obj.encrypt(plaintext[:-1])

    with pytest.raises(ValueError):
        cipher_obj.decrypt(ciphertext[:-1])


@pytest.fixture
def rsa_private(vectors):
    return RsaPrivate(vectors[RsaPrivate].key)


@pytest.fixture
def rsa_public(vectors):
    return RsaPublic(vectors[RsaPublic].key)


def test_new_rsa_raises(vectors):
    with pytest.raises(WolfCryptError):
        RsaPrivate(vectors[RsaPrivate].key[:-1])  # invalid key length

    with pytest.raises(WolfCryptError):
        RsaPublic(vectors[RsaPublic].key[:-1])    # invalid key length


def test_rsa_encrypt_decrypt(rsa_private, rsa_public):
    plaintext = t2b("Everyone gets Friday off.")

    # normal usage, encrypt with public, decrypt with pirate
    ciphertext = rsa_public.encrypt(plaintext)

    assert 1024 / 8 == len(ciphertext) == rsa_public.output_size
    assert plaintext == rsa_private.decrypt(ciphertext)

    # private object holds both private and public info, so it can also encrypt
    # using the known public key.
    ciphertext = rsa_private.encrypt(plaintext)

    assert 1024 / 8 == len(ciphertext) == rsa_private.output_size
    assert plaintext == rsa_private.decrypt(ciphertext)


def test_rsa_sign_verify(rsa_private, rsa_public):
    plaintext = t2b("Everyone gets Friday off.")

    # normal usage, sign with private, verify with public
    signature = rsa_private.sign(plaintext)

    assert 1024 / 8 == len(signature) == rsa_private.output_size
    assert plaintext == rsa_public.verify(signature)

    # private object holds both private and public info, so it can also verify
    # using the known public key.
    signature = rsa_private.sign(plaintext)

    assert 1024 / 8 == len(signature) == rsa_private.output_size
    assert plaintext == rsa_private.verify(signature)


@pytest.fixture
def ecc_private(vectors):
    return EccPrivate(vectors[EccPrivate].key)


@pytest.fixture
def ecc_public(vectors):
    return EccPublic(vectors[EccPublic].key)


def test_new_ecc_raises(vectors):
    with pytest.raises(WolfCryptError):
        EccPrivate(vectors[EccPrivate].key[:-1])  # invalid key length

    with pytest.raises(WolfCryptError):
        EccPublic(vectors[EccPublic].key[:-1])    # invalid key length

    with pytest.raises(WolfCryptError):
        EccPrivate(vectors[EccPublic].key)        # invalid key type

    with pytest.raises(WolfCryptError):
        EccPublic(vectors[EccPrivate].key)        # invalid key type

    with pytest.raises(WolfCryptError):           # invalid key size
        EccPrivate.make_key(1024)


def test_key_encoding(vectors):
    priv = EccPrivate()
    pub = EccPublic()

    priv.decode_key(vectors[EccPrivate].key)
    pub.decode_key(vectors[EccPublic].key)

    assert priv.encode_key() == vectors[EccPrivate].key
    assert pub.encode_key() == vectors[EccPublic].key


def test_x963(ecc_private, ecc_public):
    assert ecc_private.export_x963() == ecc_public.export_x963()


def test_ecc_sign_verify(ecc_private, ecc_public):
    plaintext = "Everyone gets Friday off."

    # normal usage, sign with private, verify with public
    signature = ecc_private.sign(plaintext)

    assert len(signature) <= ecc_private.max_signature_size
    assert ecc_public.verify(signature, plaintext)

    # invalid signature
    with pytest.raises(WolfCryptError):
        ecc_public.verify(signature[:-1], plaintext)

    # private object holds both private and public info, so it can also verify
    # using the known public key.
    assert ecc_private.verify(signature, plaintext)

    ecc_x963 = EccPublic()
    ecc_x963.import_x963(ecc_public.export_x963())
    assert ecc_x963.verify(signature, plaintext)

    ecc_x963 = EccPublic()
    ecc_x963.import_x963(ecc_private.export_x963())
    assert ecc_x963.verify(signature, plaintext)

    ecc_x963 = EccPublic()
    with pytest.raises(WolfCryptError):
        ecc_x963.import_x963(ecc_public.export_x963()[:-1])


def test_ecc_make_shared_secret():
    a = EccPrivate.make_key(32)
    a_pub = EccPublic()
    a_pub.import_x963(a.export_x963())

    b = EccPrivate.make_key(32)
    b_pub = EccPublic()
    b_pub.import_x963(b.export_x963())

    assert a.shared_secret(b) == \
           b.shared_secret(a) == \
           a.shared_secret(b_pub) == \
           b.shared_secret(a_pub)
