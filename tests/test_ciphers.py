# test_ciphers.py
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

# pylint: disable=redefined-outer-name

from collections import namedtuple
import pytest
from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.utils import t2b, h2b
import os

certs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

if _lib.DES3_ENABLED:
    from wolfcrypt.ciphers import Des3

if _lib.AES_ENABLED:
    from wolfcrypt.ciphers import Aes

if _lib.CHACHA_ENABLED:
    from wolfcrypt.ciphers import ChaCha

if _lib.RSA_ENABLED:
    from wolfcrypt.ciphers import (RsaPrivate, RsaPublic, HASH_TYPE_SHA256, MGF1SHA256, HASH_TYPE_SHA, MGF1SHA1)

if _lib.ECC_ENABLED:
    from wolfcrypt.ciphers import (EccPrivate, EccPublic)

if _lib.ED25519_ENABLED:
    from wolfcrypt.ciphers import (Ed25519Private, Ed25519Public)

if _lib.ED448_ENABLED:
    from wolfcrypt.ciphers import (Ed448Private, Ed448Public)

from wolfcrypt.ciphers import (
    MODE_CTR, MODE_ECB, MODE_CBC, WolfCryptError
)


@pytest.fixture
def vectors():
    TestVector = namedtuple("TestVector", """key iv plaintext ciphertext 
                ciphertext_ctr raw_key
                pkcs8_key pem""")
    TestVector.__new__.__defaults__ = (None,) * len(TestVector._fields)

    # test vector dictionary
    vectorArray = {}

    if _lib.AES_ENABLED:
        vectorArray[Aes]=TestVector(
            key="0123456789abcdef",
            iv="1234567890abcdef",
            plaintext=t2b("now is the time "),
            ciphertext=h2b("959492575f4281532ccc9d4677a233cb"),
            ciphertext_ctr = h2b('287528ddf484b1055debbe751eb52b8a')
        )
    if _lib.CHACHA_ENABLED:
        vectorArray[ChaCha]=TestVector(
            key="0123456789abcdef01234567890abcdef",
            iv="1234567890abcdef",
        )
    if _lib.DES3_ENABLED:
        vectorArray[Des3]=TestVector(
            key=h2b("0123456789abcdeffedeba987654321089abcdef01234567"),
            iv=h2b("1234567890abcdef"),
            plaintext=t2b("Now is the time for all "),
            ciphertext=h2b("43a0297ed184f80e8964843212d508981894157487127db0")
        )

    if _lib.RSA_ENABLED:
        vectorArray[RsaPublic]=TestVector(
            key=h2b(
                "30819F300D06092A864886F70D010101050003818D0030818902818100BC"
                "730EA849F374A2A9EF18A5DA559921F9C8ECB36D48E53535757737ECD161"
                "905F3ED9E4D5DF94CAC1A9D719DA86C9E84DC4613682FEABAD7E7725BB8D"
                "11A5BC623AA838CC39A20466B4F7F7F3AADA4D020EBB5E8D6948DC77C928"
                "0E22E96BA426BA4CE8C1FD4A6F2B1FEF8AAEF69062E5641EEB2B3C67C8DC"
                "2700F6916865A90203010001"),
            pem=os.path.join(certs_dir, "server-keyPub.pem")
        )
        vectorArray[RsaPrivate]=TestVector(
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
                "B105863129DBD9E2"),
            pkcs8_key=h2b(
                "30820276020100300d06092a864886f7"
                "0d0101010500048202603082025c0201"
                "0002818100bc730ea849f374a2a9ef18"
                "a5da559921f9c8ecb36d48e535357577"
                "37ecd161905f3ed9e4d5df94cac1a9d7"
                "19da86c9e84dc4613682feabad7e7725"
                "bb8d11a5bc623aa838cc39a20466b4f7"
                "f7f3aada4d020ebb5e8d6948dc77c928"
                "0e22e96ba426ba4ce8c1fd4a6f2b1fef"
                "8aaef69062e5641eeb2b3c67c8dc2700"
                "f6916865a902030100010281801397ea"
                "e8387825a25c04ce0d407c31e5c470cd"
                "9b823b5809863b665fdc3190f14fd5db"
                "15ddded73b95933118310e5ea3d6a21a"
                "716e81481c4bcfdb8e7a866132dcfb55"
                "c1166d279224458bf1b848b14b1dacde"
                "dadd8e2fc291fba5a96ef83a6af1fd50"
                "18ef9fe7c3ca78ea56d3d3725b96dd4e"
                "064e3ac3d9be72b66507074c01024100"
                "fa47d47a7c923c55ef81f041302da3cf"
                "8f1ce6872705700ddf9835d6f18b382f"
                "24b5d084b6794f7129945af0646aace7"
                "72c6ed4d59983e673af3742cf9611769"
                "024100c0c1820d0cebc62fdc92f99d82"
                "1a31e9e9f74bf282871cee166ad11d18"
                "8270f3c0b62ff6f3f71df18623c84eeb"
                "8f568e8ff5bff1f72bb5cc3dc657390c"
                "1b54410241009d7e05deedf4b7b2fbfc"
                "304b551de32f0147966905cd0e2e2cbd"
                "8363b6ab7cb76dca5b64a7cebe86df3b"
                "53de61d21eeba5f637edacab78d94ce7"
                "55fbd71199c1024018981829e61e2739"
                "702168ac0a2fa172c121869538c65890"
                "a0579cbae3a7b115c8def61bc2612376"
                "efb09d1c44be1343396717c89dcafbf5"
                "45648b38822cf28102403989e59c1955"
                "30bab7488c48140ef49f7e779743e1b4"
                "19353123759c3b44ad691256ee006164"
                "1666d37c742b15b4a2febf086b1a5d3f"
                "9012b105863129dbd9e2"),
            pem=os.path.join(certs_dir, "server-key.pem")
        )

    if _lib.ECC_ENABLED:
        vectorArray[EccPublic]=TestVector(
            key=h2b(
                "3059301306072A8648CE3D020106082A8648CE3D0301070342000455BFF4"
                "0F44509A3DCE9BB7F0C54DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                "EFA2351243847616C6569506CC01A9BDF6751A42F7BDA9B236225FC75D7F"
                "B4"
            ),
            raw_key=h2b(
                "55bff40f44509a3dce9bb7f0c54df5707bd4ec248e1980ec5a4ca22403622c9b"
                "daefa2351243847616c6569506cc01a9bdf6751a42f7bda9b236225fc75d7fb4"
            )
        )
        vectorArray[EccPrivate]=TestVector(
            key=h2b(
                "30770201010420F8CF926BBD1E28F1A8ABA1234F3274188850AD7EC7EC92"
                "F88F974DAF568965C7A00A06082A8648CE3D030107A1440342000455BFF4"
                "0F44509A3DCE9BB7F0C54DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                "EFA2351243847616C6569506CC01A9BDF6751A42F7BDA9B236225FC75D7F"
                "B4"
            ),
            raw_key=h2b(
                "55bff40f44509a3dce9bb7f0c54df5707bd4ec248e1980ec5a4ca22403622c9b"
                "daefa2351243847616c6569506cc01a9bdf6751a42f7bda9b236225fc75d7fb4"
                "f8cf926bbd1e28f1a8aba1234f3274188850ad7ec7ec92f88f974daf568965c7"
            )
        )

    if _lib.ED25519_ENABLED:
        vectorArray[Ed25519Private]=TestVector(
             key = h2b(
                 "47CD22B276161AA18BA1E0D13DBE84FE4840E4395D784F555A92E8CF739B"
                 "F86B"
            )
        )
        vectorArray[Ed25519Public]=TestVector(
            key=h2b(
                "8498C65F4841145F9C51E8BFF4504B5527E0D5753964B7CB3C707A2B9747"
                "FC96"
            )
        )
    if _lib.ED448_ENABLED:
        vectorArray[Ed448Private]=TestVector(
            key=h2b("c2b29804e9a893c9e275cac1f8a3033f3d4b78b79eb427ed359fdeb8"
                    "82d657c129c7930936b181971b795167ad18cabeeb52b59b94f115ad"
                    "59"
            )
        )
        vectorArray[Ed448Public]=TestVector(
            key=h2b("89fb2b5a5ab67dd317794cc5f1700cace295b043f3ad73a66299e10a"
                    "d3fc0a28289ddd1c641598a354113867a42e82ad844b4d858d92e4e7"
                    "80"
            )
        )
    return vectorArray

algo_params = []
if _lib.AES_ENABLED:
    algo_params.append(Aes)
if _lib.DES3_ENABLED:
    algo_params.append(Des3)

@pytest.fixture(params=algo_params)
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
    ciphertext_ctr = vectors[cipher_cls].ciphertext_ctr

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


    # Test AES in counter mode
    if ciphertext_ctr is not None:
        cipher_obj = cipher_cls.new(key, MODE_CTR, iv)
        res = cipher_obj.encrypt(plaintext)
        assert res == ciphertext_ctr
        cipher_obj = cipher_cls.new(key, MODE_CTR, iv)
        assert plaintext == cipher_obj.decrypt(res)

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

if _lib.CHACHA_ENABLED:
    @pytest.fixture
    def chacha_obj(vectors):
        r = ChaCha(vectors[ChaCha].key, 32)
        r.set_iv(vectors[ChaCha].iv)
        return r

    @pytest.fixture
    def test_chacha_enc_dec(chacha_obj):
        plaintext = t2b("Everyone gets Friday off.")
        cyt = chacha_obj.encrypt(plaintext)
        chacha_obj.set_iv(vectors[ChaCha].iv)
        dec = chacha_obj.decrypt(cyt)
        assert plaintext == dec




if _lib.RSA_ENABLED:
    @pytest.fixture
    def rsa_private(vectors):
        return RsaPrivate(vectors[RsaPrivate].key)

    @pytest.fixture
    def rsa_private_oaep(vectors):
        return RsaPrivate(vectors[RsaPrivate].key, hash_type=HASH_TYPE_SHA)

    @pytest.fixture
    def rsa_private_pss(vectors):
        return RsaPrivate(vectors[RsaPrivate].key, hash_type=HASH_TYPE_SHA256)

    @pytest.fixture
    def rsa_private_pkcs8(vectors):
        return RsaPrivate(vectors[RsaPrivate].pkcs8_key)

    @pytest.fixture
    def rsa_public(vectors):
        return RsaPublic(vectors[RsaPublic].key)

    @pytest.fixture
    def rsa_public_oaep(vectors):
        return RsaPublic(vectors[RsaPublic].key, hash_type=HASH_TYPE_SHA)

    @pytest.fixture
    def rsa_public_pss(vectors):
        return RsaPublic(vectors[RsaPublic].key, hash_type=HASH_TYPE_SHA256)

    @pytest.fixture
    def rsa_private_pem(vectors):
        with open(vectors[RsaPrivate].pem, "rb") as f:
            pem = f.read()
        return RsaPrivate.from_pem(pem)

    @pytest.fixture
    def rsa_public_pem(vectors):
        with open(vectors[RsaPublic].pem, "rb") as f:
            pem = f.read()
        return RsaPublic.from_pem(pem)


    def test_new_rsa_raises(vectors):
        with pytest.raises(WolfCryptError):
            RsaPrivate(vectors[RsaPrivate].key[:-1])  # invalid key length

        with pytest.raises(WolfCryptError):
            RsaPublic(vectors[RsaPublic].key[:-1])    # invalid key length

        if _lib.KEYGEN_ENABLED:
            with pytest.raises(WolfCryptError):           # invalid key size
                RsaPrivate.make_key(16384)


    def test_rsa_encrypt_decrypt(rsa_private, rsa_public):
        plaintext = t2b("Everyone gets Friday off.")

        # normal usage, encrypt with public, decrypt with private
        ciphertext = rsa_public.encrypt(plaintext)

        assert 1024 / 8 == len(ciphertext) == rsa_public.output_size
        assert plaintext == rsa_private.decrypt(ciphertext)

        # private object holds both private and public info, so it can also encrypt
        # using the known public key.
        ciphertext = rsa_private.encrypt(plaintext)

        assert 1024 / 8 == len(ciphertext) == rsa_private.output_size
        assert plaintext == rsa_private.decrypt(ciphertext)

    def test_rsa_encrypt_decrypt_pad_oaep(rsa_private_oaep, rsa_public_oaep):
        plaintext = t2b("Everyone gets Friday off.")

        # normal usage, encrypt with public, decrypt with private
        ciphertext = rsa_public_oaep.encrypt_oaep(plaintext)

        assert 1024 / 8 == len(ciphertext) == rsa_public_oaep.output_size
        assert plaintext == rsa_private_oaep.decrypt_oaep(ciphertext)

        # private object holds both private and public info, so it can also encrypt
        # using the known public key.
        ciphertext = rsa_private_oaep.encrypt_oaep(plaintext)

        assert 1024 / 8 == len(ciphertext) == rsa_private_oaep.output_size
        assert plaintext == rsa_private_oaep.decrypt_oaep(ciphertext)


    def test_rsa_pkcs8_encrypt_decrypt(rsa_private_pkcs8, rsa_public):
        plaintext = t2b("Everyone gets Friday off.")

        # normal usage, encrypt with public, decrypt with private
        ciphertext = rsa_public.encrypt(plaintext)

        assert 1024 / 8 == len(ciphertext) == rsa_public.output_size
        assert plaintext == rsa_private_pkcs8.decrypt(ciphertext)

        # private object holds both private and public info, so it can also encrypt
        # using the known public key.
        ciphertext = rsa_private_pkcs8.encrypt(plaintext)

        assert 1024 / 8 == len(ciphertext) == rsa_private_pkcs8.output_size
        assert plaintext == rsa_private_pkcs8.decrypt(ciphertext)


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

    if _lib.RSA_PSS_ENABLED:
        def test_rsa_pss_sign_verify(rsa_private_pss, rsa_public_pss):
            plaintext = t2b("Everyone gets Friday off.")

            # normal usage, sign with private, verify with public
            signature = rsa_private_pss.sign_pss(plaintext)

            assert 1024 / 8 == len(signature) == rsa_private_pss.output_size
            assert 0 == rsa_public_pss.verify_pss(plaintext, signature)

            # private object holds both private and public info, so it can also verify
            # using the known public key.
            signature = rsa_private_pss.sign_pss(plaintext)

            assert 1024 / 8 == len(signature) == rsa_private_pss.output_size
            assert 0 == rsa_private_pss.verify_pss(plaintext, signature)

    def test_rsa_sign_verify_pem(rsa_private_pem, rsa_public_pem):
        plaintext = t2b("Everyone gets Friday off.")

        # normal usage, sign with private, verify with public
        signature = rsa_private_pem.sign(plaintext)

        assert 256 == len(signature) == rsa_private_pem.output_size
        assert plaintext == rsa_public_pem.verify(signature)

        # private object holds both private and public info, so it can also verify
        # using the known public key.
        signature = rsa_private_pem.sign(plaintext)

        assert 256 == len(signature) == rsa_private_pem.output_size
        assert plaintext == rsa_private_pem.verify(signature)

    def test_rsa_pkcs8_sign_verify(rsa_private_pkcs8, rsa_public):
        plaintext = t2b("Everyone gets Friday off.")

        # normal usage, sign with private, verify with public
        signature = rsa_private_pkcs8.sign(plaintext)

        assert 1024 / 8 == len(signature) == rsa_private_pkcs8.output_size
        assert plaintext == rsa_public.verify(signature)

        # private object holds both private and public info, so it can also verify
        # using the known public key.
        signature = rsa_private_pkcs8.sign(plaintext)

        assert 1024 / 8 == len(signature) == rsa_private_pkcs8.output_size
        assert plaintext == rsa_private_pkcs8.verify(signature)


if _lib.ECC_ENABLED:
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

        with pytest.raises(WolfCryptError):           # invalid key size
            EccPrivate.make_key(1024)


    def test_key_encoding(vectors):
        priv = EccPrivate()
        pub = EccPublic()
        raw_priv = EccPrivate()
        raw_pub = EccPublic()


        # Test default encode/decode key
        priv.decode_key(vectors[EccPrivate].key)
        pub.decode_key(vectors[EccPublic].key)
        assert priv.encode_key() == vectors[EccPrivate].key
        assert pub.encode_key() == vectors[EccPublic].key

        # Test EccPrivate.encode_key_raw/decode_key_raw
        key = vectors[EccPrivate].raw_key
        raw_priv.decode_key_raw(key[0:32], key[32:64], key[64:96])
        qx, qy, d = raw_priv.encode_key_raw()
        assert qx[0:32] == vectors[EccPrivate].raw_key[0:32]
        assert qy[0:32] == vectors[EccPrivate].raw_key[32:64]
        assert d[0:32] == vectors[EccPrivate].raw_key[64:96]
        # Verify ECC key is the same as the raw key
        qx, qy, d = priv.encode_key_raw()
        assert qx[0:32] == vectors[EccPrivate].raw_key[0:32]
        assert qy[0:32] == vectors[EccPrivate].raw_key[32:64]
        assert d[0:32] == vectors[EccPrivate].raw_key[64:96]

        # Test EccPublic.encode_key_raw/decode_key_raw
        key = vectors[EccPublic].raw_key
        raw_pub.decode_key_raw(key[0:32], key[32:64])
        qx, qy = raw_pub.encode_key_raw()
        assert qx[0:32] == vectors[EccPublic].raw_key[0:32]
        assert qy[0:32] == vectors[EccPublic].raw_key[32:64]
        # Verify ECC public key is the same as the raw key
        qx, qy = pub.encode_key_raw()
        assert qx[0:32] == vectors[EccPublic].raw_key[0:32]
        assert qy[0:32] == vectors[EccPublic].raw_key[32:64]





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

    if _lib.MPAPI_ENABLED:
        def test_ecc_sign_verify_raw(ecc_private, ecc_public):
            plaintext = "Everyone gets Friday off."

            # normal usage, sign with private, verify with public
            r,s = ecc_private.sign_raw(plaintext)

            assert len(r) + len(s) <= 2 * ecc_private.size
            assert ecc_public.verify_raw(r, s, plaintext)

            # invalid signature
            ret = ecc_public.verify_raw(r, s[:-1], plaintext)
            assert ret == False

            # private object holds both private and public info, so it can also verify
            # using the known public key.
            assert ecc_private.verify_raw(r, s, plaintext)


    def test_ecc_make_shared_secret():
        a = EccPrivate.make_key(32)
        a_pub = EccPublic()
        a_pub.import_x963(a.export_x963())

        b = EccPrivate.make_key(32)
        b_pub = EccPublic()
        b_pub.import_x963(b.export_x963())

        assert a.shared_secret(b) \
            == b.shared_secret(a) \
            == a.shared_secret(b_pub) \
            == b.shared_secret(a_pub)

if _lib.ED25519_ENABLED:
    @pytest.fixture
    def ed25519_private(vectors):
        return Ed25519Private(vectors[Ed25519Private].key, vectors[Ed25519Public].key)


    @pytest.fixture
    def ed25519_public(vectors):
        return Ed25519Public(vectors[Ed25519Public].key)


    def test_new_ed25519_raises(vectors):
        with pytest.raises(WolfCryptError):
            Ed25519Private(vectors[Ed25519Private].key[:-1])  # invalid key length

        with pytest.raises(WolfCryptError):
            Ed25519Public(vectors[Ed25519Public].key[:-1])    # invalid key length

        with pytest.raises(WolfCryptError):           # invalid key size
            Ed25519Private.make_key(1024)


    def test_ed25519_key_encoding(vectors):
        priv = Ed25519Private()
        pub = Ed25519Public()

        priv.decode_key(vectors[Ed25519Private].key)
        pub.decode_key(vectors[Ed25519Public].key)

        assert priv.encode_key()[0] == vectors[Ed25519Private].key
        assert priv.encode_key()[1] == vectors[Ed25519Public].key # Automatically re-generated from private-only
        assert pub.encode_key() == vectors[Ed25519Public].key


    def test_ed25519_sign_verify(ed25519_private, ed25519_public):
        plaintext = "Everyone gets Friday off."

        # normal usage, sign with private, verify with public
        signature = ed25519_private.sign(plaintext)

        assert len(signature) <= ed25519_private.max_signature_size
        assert ed25519_public.verify(signature, plaintext)

        # invalid signature
        with pytest.raises(WolfCryptError):
            ed25519_public.verify(signature[:-1], plaintext)

        # private object holds both private and public info, so it can also verify
        # using the known public key.
        assert ed25519_private.verify(signature, plaintext)

if _lib.ED448_ENABLED:
    @pytest.fixture
    def ed448_private(vectors):
        return Ed448Private(vectors[Ed448Private].key, vectors[Ed448Public].key)


    @pytest.fixture
    def ed448_public(vectors):
        return Ed448Public(vectors[Ed448Public].key)


    def test_new_ed448_raises(vectors):
        with pytest.raises(WolfCryptError):
            Ed448Private(vectors[Ed448Private].key[:-1])  # invalid key length

        with pytest.raises(WolfCryptError):
            Ed448Public(vectors[Ed448Public].key[:-1])    # invalid key length

        with pytest.raises(WolfCryptError):           # invalid key size
            Ed448Private.make_key(1024)


    def test_ed448_key_encoding(vectors):
        priv = Ed448Private()
        pub = Ed448Public()

        priv.decode_key(vectors[Ed448Private].key)
        pub.decode_key(vectors[Ed448Public].key)

        assert priv.encode_key()[0] == vectors[Ed448Private].key
        assert priv.encode_key()[1] == vectors[Ed448Public].key # Automatically re-generated from private-only
        assert pub.encode_key() == vectors[Ed448Public].key


    def test_ed448_sign_verify(ed448_private, ed448_public):
        plaintext = "Everyone gets Friday off."

        # normal usage, sign with private, verify with public
        signature = ed448_private.sign(plaintext)

        assert len(signature) <= ed448_private.max_signature_size
        assert ed448_public.verify(signature, plaintext)

        # invalid signature
        with pytest.raises(WolfCryptError):
            ed448_public.verify(signature[:-1], plaintext)

        # private object holds both private and public info, so it can also verify
        # using the known public key.
        assert ed448_private.verify(signature, plaintext)
