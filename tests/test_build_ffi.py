# test_build_ffi.py
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# pylint: disable=redefined-outer-name

"""Tests for feature detection and cdef generation in scripts/build_ffi.py.

Nothing here builds wolfSSL or compiles C code.
"""

import importlib.util
import os
import re

import pytest
from cffi import FFI

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_FFI = os.path.join(ROOT, "scripts", "build_ffi.py")

pytestmark = pytest.mark.filterwarnings("ignore:The distutils package is deprecated:DeprecationWarning")

# Sub-capability -> the capability it depends on. Reference configurations
# must enable every sub-capability whenever its parent is enabled.
SUBCAPABILITIES = {
    "AES_CTR": "AES",
    "AES_CBC": "AES",
    "AES_DECRYPT": "AES",
    "AESGCM_STREAM_DECRYPT": "AESGCM_STREAM",
    "SHA3_224": "SHA3",
    "SHA3_256": "SHA3",
    "SHA3_384": "SHA3",
    "SHA3_512": "SHA3",
    "HKDF": "HMAC",
    "PBKDF2": "PWDBASED",
    "PEM_TO_DER": "ASN",
    "DER_TO_PEM": "ASN",
    "PKCS8": "ASN",
    "RSA_ENCRYPT": "RSA",
    "RSA_PRIVATE": "RSA",
    "RSA_SIGN": "RSA",
    "RSA_VERIFY": "RSA",
    "RSA_OAEP": "RSA",
    "ECC_SIGN": "ECC",
    "ECC_VERIFY": "ECC",
    "ECC_DHE": "ECC",
    "ECC_KEY_IMPORT": "ECC",
    "ECC_KEY_EXPORT": "ECC",
    "ED25519_MAKE_KEY": "ED25519",
    "ED25519_SIGN": "ED25519",
    "ED25519_VERIFY": "ED25519",
    "ED25519_KEY_IMPORT": "ED25519",
    "ED25519_KEY_EXPORT": "ED25519",
    "ED448_SIGN": "ED448",
    "ED448_VERIFY": "ED448",
    "ED448_KEY_IMPORT": "ED448",
    "ED448_KEY_EXPORT": "ED448",
    "ML_KEM_MAKE_KEY": "ML_KEM",
    "ML_KEM_ENCAPSULATE": "ML_KEM",
    "ML_KEM_DECAPSULATE": "ML_KEM",
    "ML_DSA_MAKE_KEY": "ML_DSA",
    "ML_DSA_SIGN": "ML_DSA",
    "ML_DSA_VERIFY": "ML_DSA",
    "ML_DSA_PUBLIC_KEY": "ML_DSA",
    "ML_DSA_PRIVATE_KEY": "ML_DSA",
}


@pytest.fixture(scope="module")
def bf():
    if not os.path.exists(BUILD_FFI):
        pytest.skip("scripts/build_ffi.py not available")
    spec = importlib.util.spec_from_file_location("wolfcrypt_build_ffi", BUILD_FFI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def detect(bf, *defines, fips=False):
    return bf.detect_features(list(defines), bf.default_features(), fips)


def cdef_for(bf, features):
    cdef = bf.make_cdef(features)
    FFI().cdef(cdef)  # parse only, no compiler
    return cdef


def test_import_has_no_side_effects(bf):
    # set_source() stores cffi's private _assigned_source attribute.
    assert not hasattr(bf.ffibuilder, "_assigned_source")


def test_flags_declared_and_defined(bf):
    features = bf.default_features()
    declared = set(re.findall(r"extern int (\w+);", cdef_for(bf, features)))
    defined = set(re.findall(r"^\s*int (\w+) = ", bf.make_source(features), re.MULTILINE))
    assert declared
    assert declared == defined


@pytest.mark.parametrize("config", ["non_fips", "fips_ready", "bundled"])
def test_reference_configs_enable_all_subcapabilities(bf, config):
    if config == "bundled":
        path = os.path.join(ROOT, "lib", "wolfssl", bf.get_platform(), bf.version,
                            "include", "wolfssl", "options.h")
    else:
        path = os.path.join(ROOT, "windows", config, "user_settings.h")
    if not os.path.exists(path):
        pytest.skip(f"{path} not available")
    with open(path) as f:
        features = detect(bf, *f.read().splitlines(), fips=config == "fips_ready")
    for sub, parent in SUBCAPABILITIES.items():
        assert features[sub] == features[parent], sub
    assert features["RNG"] == 1


def test_detection_matches_indented_defines_with_values(bf):
    assert detect(bf, "  #  define WOLFSSL_AES_COUNTER 1 /* CTR */")["AES_CTR"] == 1
    assert detect(bf, "/* #define WOLFSSL_AES_COUNTER */")["AES_CTR"] == 0
    assert detect(bf, "#define WOLFSSL_AES_COUNTER_X")["AES_CTR"] == 0


def test_aes_ctr_needs_aes_counter(bf):
    features = detect(bf)
    assert features["AES_CTR"] == 0
    assert "wc_AesCtrEncrypt" not in cdef_for(bf, features)

    features = detect(bf, "#define WOLFSSL_AES_COUNTER")
    assert features["AES_CTR"] == 1
    assert "wc_AesCtrEncrypt" in cdef_for(bf, features)

    features = detect(bf, "#define NO_AES", "#define WOLFSSL_AES_COUNTER")
    assert features["AES_CTR"] == 0
    assert "wc_AesCtrEncrypt" not in cdef_for(bf, features)


def test_aes_cbc_needs_cbc_support(bf):
    features = detect(bf)
    assert features["AES_CBC"] == 1
    cdef = cdef_for(bf, features)
    assert "wc_AesCbcEncrypt" in cdef
    assert "wc_AesCbcDecrypt" in cdef

    for define in ("#define NO_AES_CBC", "    #define NO_AES_CBC 1", "#define NO_AES"):
        features = detect(bf, define)
        assert features["AES_CBC"] == 0, define
        cdef = cdef_for(bf, features)
        assert "wc_AesCbcEncrypt" not in cdef, define
        assert "wc_AesCbcDecrypt" not in cdef, define


def test_aes_cbc_decrypt_needs_aes_decrypt(bf):
    features = detect(bf)
    assert features["AES_DECRYPT"] == 1

    features = detect(bf, "#define NO_AES_DECRYPT")
    assert features["AES_DECRYPT"] == 0
    assert features["AES_CBC"] == 1
    cdef = cdef_for(bf, features)
    assert "wc_AesCbcEncrypt" in cdef
    assert "wc_AesCbcDecrypt" not in cdef

    assert detect(bf, "#define NO_AES")["AES_DECRYPT"] == 0


def test_aesgcm_stream_decrypt_needs_decrypt_support(bf):
    stream = "#define WOLFSSL_AESGCM_STREAM"
    decrypt_funcs = ("wc_AesGcmDecryptInit", "wc_AesGcmDecryptUpdate", "wc_AesGcmDecryptFinal")

    features = detect(bf, stream)
    assert features["AESGCM_STREAM_DECRYPT"] == 1
    cdef = cdef_for(bf, features)
    for name in decrypt_funcs:
        assert name in cdef, name

    features = detect(bf, stream, "#define NO_AES_DECRYPT")
    assert features["AESGCM_STREAM_DECRYPT"] == 0
    cdef = cdef_for(bf, features)
    assert "wc_AesGcmEncryptUpdate" in cdef
    assert "wc_AesFree" in cdef
    for name in decrypt_funcs:
        assert name not in cdef, name

    # aes.c also builds GCM decryption with HAVE_AESGCM_DECRYPT.
    features = detect(bf, stream, "#define NO_AES_DECRYPT", "#define HAVE_AESGCM_DECRYPT")
    assert features["AESGCM_STREAM_DECRYPT"] == 1
    assert "wc_AesGcmDecryptUpdate" in cdef_for(bf, features)

    assert detect(bf, "#define NO_AES", stream, "#define HAVE_AESGCM_DECRYPT")["AESGCM_STREAM_DECRYPT"] == 0
    assert detect(bf)["AESGCM_STREAM_DECRYPT"] == 0


SHA3_BITS = (224, 256, 384, 512)


def sha3_funcs(bits):
    return (f"wc_InitSha3_{bits}", f"wc_Sha3_{bits}_Update", f"wc_Sha3_{bits}_Final",
            f"wc_Sha3_{bits}_Free", f"wc_Sha3_{bits}_Copy")


def test_sha3_variants_follow_nosha3_macros(bf):
    sha3 = "#define WOLFSSL_SHA3"

    features = detect(bf, sha3)
    cdef = cdef_for(bf, features)
    for bits in SHA3_BITS:
        assert features[f"SHA3_{bits}"] == 1, bits
        for name in sha3_funcs(bits):
            assert name in cdef, name

    for disabled in SHA3_BITS:
        features = detect(bf, sha3, f"#define WOLFSSL_NOSHA3_{disabled}")
        cdef = cdef_for(bf, features)
        assert "wc_Sha3;" in cdef
        for bits in SHA3_BITS:
            enabled = bits != disabled
            assert features[f"SHA3_{bits}"] == enabled, (disabled, bits)
            for name in sha3_funcs(bits):
                assert (name in cdef) == enabled, (disabled, name)

    assert detect(bf, sha3, "    #define WOLFSSL_NOSHA3_512 1")["SHA3_512"] == 0

    # settings.h keeps only SHA3-384 on Xilinx.
    for xilinx in ("#define WOLFSSL_XILINX_CRYPT", "#define WOLFSSL_AFALG_XILINX"):
        features = detect(bf, sha3, xilinx)
        assert [features[f"SHA3_{bits}"] for bits in SHA3_BITS] == [0, 0, 1, 0], xilinx

    features = detect(bf)
    for bits in SHA3_BITS:
        assert features[f"SHA3_{bits}"] == 0, bits


def test_hkdf_needs_hmac(bf):
    hkdf_funcs = ("wc_HKDF(", "wc_HKDF_Extract(", "wc_HKDF_Extract_ex(", "wc_HKDF_Expand(", "wc_HKDF_Expand_ex(")

    features = detect(bf, "#define HAVE_HKDF")
    assert features["HKDF"] == 1
    cdef = cdef_for(bf, features)
    for name in hkdf_funcs:
        assert name in cdef, name

    # hmac.h and hmac.c provide HKDF only without NO_HMAC.
    features = detect(bf, "#define HAVE_HKDF", "#define NO_HMAC")
    assert features["HMAC"] == 0
    assert features["HKDF"] == 0
    cdef = cdef_for(bf, features)
    for name in hkdf_funcs:
        assert name not in cdef, name

    assert detect(bf)["HKDF"] == 0


def test_pbkdf2_needs_hmac_and_pbkdf2(bf):
    features = detect(bf)
    assert features["PBKDF2"] == 1
    assert "wc_PBKDF2(" in cdef_for(bf, features)

    # pwdbased.c builds wc_PBKDF2 only with HAVE_PBKDF2 and without NO_HMAC.
    for define in ("#define NO_HMAC", "#define NO_PBKDF2", "  #define NO_PBKDF2 1", "#define NO_PWDBASED"):
        features = detect(bf, define)
        assert features["PBKDF2"] == 0, define
        assert "wc_PBKDF2(" not in cdef_for(bf, features), define

    # settings.h defines HAVE_PBKDF2 for PKCS7 and scrypt even with NO_PBKDF2.
    for define in ("#define HAVE_PBKDF2", "#define HAVE_PKCS7", "#define HAVE_SCRYPT"):
        features = detect(bf, "#define NO_PBKDF2", define)
        assert features["PBKDF2"] == 1, define
        assert "wc_PBKDF2(" in cdef_for(bf, features), define

    assert detect(bf, "#define NO_HMAC", "#define HAVE_PKCS7")["PBKDF2"] == 0


PEM_TO_DER_DECLS = ("DerBuffer", "EncryptedInfo", "wc_PemToDer(", "wc_FreeDer(")


def test_pem_der_conversions_follow_their_own_macros(bf):
    # settings.h derives WOLFSSL_DER_TO_PEM only from KEY_GEN, CERT_GEN or OPENSSL_EXTRA.
    features = detect(bf)
    assert features["PEM_TO_DER"] == 1
    assert features["DER_TO_PEM"] == 0
    cdef = cdef_for(bf, features)
    assert "wc_EncodeSignature(" in cdef
    for name in PEM_TO_DER_DECLS:
        assert name in cdef, name
    assert "wc_DerToPemEx(" not in cdef

    for define in ("#define WOLFSSL_KEY_GEN", "  #define WOLFSSL_KEY_GEN 1", "#define WOLFSSL_CERT_GEN",
                   "#define OPENSSL_EXTRA", "#define OPENSSL_ALL", "#define WOLFSSL_DUAL_ALG_CERTS",
                   "#define WOLFSSL_DER_TO_PEM"):
        features = detect(bf, define)
        assert features["DER_TO_PEM"] == 1, define
        assert "wc_DerToPemEx(" in cdef_for(bf, features), define

    features = detect(bf, "#define WOLFSSL_KEY_GEN", "#define WOLFSSL_NO_DER_TO_PEM")
    assert features["DER_TO_PEM"] == 0
    assert "wc_DerToPemEx(" not in cdef_for(bf, features)
    assert detect(bf, "#define WOLFSSL_CERT_GEN", "#define WOLFSSL_NO_DER_TO_PEM")["DER_TO_PEM"] == 1

    # settings.h derives WOLFSSL_PEM_TO_DER unless WOLFSSL_NO_PEM or NO_CODING.
    for define in ("#define WOLFSSL_NO_PEM", "#define NO_CODING", "    #define NO_CODING 1"):
        features = detect(bf, "#define WOLFSSL_KEY_GEN", define)
        assert features["PEM_TO_DER"] == 0, define
        assert features["DER_TO_PEM"] == 1, define
        cdef = cdef_for(bf, features)
        assert "wc_EncodeSignature(" in cdef, define
        assert "wc_DerToPemEx(" in cdef, define
        for name in PEM_TO_DER_DECLS:
            assert name not in cdef, (define, name)
    assert detect(bf, "#define WOLFSSL_NO_PEM", "#define WOLFSSL_PEM_TO_DER")["PEM_TO_DER"] == 1

    # asn.c builds both directions only with ASN and certificate support.
    for define in ("#define NO_ASN", "#define NO_CERTS"):
        features = detect(bf, "#define WOLFSSL_KEY_GEN", define)
        assert features["PEM_TO_DER"] == 0, define
        assert features["DER_TO_PEM"] == 0, define
        cdef = cdef_for(bf, features)
        for name in (*PEM_TO_DER_DECLS, "wc_DerToPemEx("):
            assert name not in cdef, (define, name)


def test_pkcs8_offset_needs_pkcs8(bf):
    helper = "wc_GetPkcs8TraditionalOffset("

    features = detect(bf)
    assert features["PKCS8"] == 1
    assert helper in cdef_for(bf, features)

    # settings.h defines HAVE_PKCS8 unless both NO_PKCS8 and NO_PKCS12.
    for define in ("#define NO_PKCS8", "#define NO_PKCS12"):
        features = detect(bf, define)
        assert features["PKCS8"] == 1, define
        assert helper in cdef_for(bf, features), define

    features = detect(bf, "#define NO_PKCS8", "  #define NO_PKCS12 1")
    assert features["PKCS8"] == 0
    assert features["RSA"] == 1
    assert helper not in cdef_for(bf, features)

    for define in ("#define HAVE_PKCS8", "#define HAVE_PKCS12"):
        assert detect(bf, "#define NO_PKCS8", "#define NO_PKCS12", define)["PKCS8"] == 1, define

    # asn.c builds it only without NO_ASN, even with RSA.
    features = detect(bf, "#define NO_ASN")
    assert features["RSA"] == 1
    assert features["PKCS8"] == 0
    assert helper not in cdef_for(bf, features)


RNG_DECLS = ("wc_InitRng(", "wc_InitRngNonce(", "wc_InitRngNonce_ex(", "wc_RNG_GenerateBlock(",
             "wc_RNG_GenerateByte(", "wc_FreeRng(", "wc_RNG_DRBG_Reseed(", "wc_GenerateSeed(",
             "wc_SetSeed_Cb(", "wc_RsaSetRNG(")


def test_rng_api_needs_rng(bf):
    optional = ("#define WC_RNG_SEED_CB", "#define WC_RSA_BLINDING")

    features = detect(bf, *optional)
    assert features["RNG"] == 1
    cdef = cdef_for(bf, features)
    for name in RNG_DECLS:
        assert name in cdef, name

    # random.h replaces the RNG API with macros under WC_NO_RNG. random.c and
    # rsa.c then build no RNG, DRBG, seed or RSA blinding functions.
    for define in ("#define WC_NO_RNG", "  #define WC_NO_RNG 1"):
        features = detect(bf, define, *optional)
        for name in ("RNG", "HASHDRBG", "WC_RNG_SEED_CB", "RSA_BLINDING"):
            assert features[name] == 0, (define, name)
        cdef = cdef_for(bf, features)
        assert "WC_RNG;" in cdef, define
        for name in RNG_DECLS:
            assert name not in cdef, (define, name)


RSA_OPS = ("wc_RsaPublicEncrypt(", "wc_RsaPublicEncrypt_ex(", "wc_RsaPrivateDecrypt(",
           "wc_RsaPrivateDecrypt_ex(", "wc_RsaSSL_Sign(", "wc_RsaSSL_Verify(", "wc_RsaPSS_Sign(",
           "wc_MakeRsaKey(")
RSA_SUBSETS = ("RSA_ENCRYPT", "RSA_PRIVATE", "RSA_SIGN", "RSA_VERIFY", "RSA_OAEP")


@pytest.mark.parametrize(("defines", "disabled", "absent"), [
    ((), (), ()),
    # --enable-rsapub
    (("#define WOLFSSL_RSA_PUBLIC_ONLY",), ("RSA_PRIVATE", "RSA_SIGN"),
     ("wc_RsaPrivateDecrypt(", "wc_RsaPrivateDecrypt_ex(", "wc_RsaSSL_Sign(", "wc_RsaPSS_Sign(",
      "wc_MakeRsaKey(")),
    (("#define WOLFSSL_RSA_VERIFY_ONLY",), ("RSA_ENCRYPT", "RSA_SIGN"),
     ("wc_RsaPublicEncrypt(", "wc_RsaPublicEncrypt_ex(", "wc_RsaSSL_Sign(", "wc_RsaPSS_Sign(")),
    (("#define WOLFSSL_RSA_VERIFY_INLINE",), ("RSA_VERIFY",), ("wc_RsaSSL_Verify(",)),
    # --enable-rsavfy
    (("#define WOLFSSL_RSA_PUBLIC_ONLY", "#define WOLFSSL_RSA_VERIFY_ONLY", "#define WOLFSSL_RSA_VERIFY_INLINE"),
     ("RSA_ENCRYPT", "RSA_PRIVATE", "RSA_SIGN", "RSA_VERIFY"), RSA_OPS),
    # --disable-oaep
    (("#define WC_NO_RSA_OAEP",), ("RSA_OAEP",), ("wc_RsaPublicEncrypt_ex(", "wc_RsaPrivateDecrypt_ex(")),
    (("  #define WC_NO_RSA_OAEP 1",), ("RSA_OAEP",), ("wc_RsaPublicEncrypt_ex(", "wc_RsaPrivateDecrypt_ex(")),
], ids=["default", "public-only", "verify-only", "verify-inline", "rsavfy", "no-oaep", "no-oaep-indented"])
def test_rsa_operations_follow_subset_macros(bf, defines, disabled, absent):
    features = detect(bf, "#define WOLFSSL_KEY_GEN", "#define WC_RSA_PSS", *defines)
    for name in RSA_SUBSETS:
        assert features[name] == (name not in disabled), name
    cdef = cdef_for(bf, features)
    for name in RSA_OPS:
        assert (name in cdef) == (name not in absent), name
    # Key decoding and encoding and PSS verification stay available.
    for name in ("wc_RsaPublicKeyDecode(", "wc_RsaPrivateKeyDecode(", "wc_RsaKeyToDer(",
                 "wc_RsaKeyToPublicDer(", "wc_RsaPSS_Verify(", "wc_RsaPSS_CheckPadding("):
        assert name in cdef, name


def test_rsa_subsets_need_rsa(bf):
    features = detect(bf, "#define NO_RSA")
    for name in RSA_SUBSETS:
        assert features[name] == 0, name
    cdef = cdef_for(bf, features)
    for name in RSA_OPS:
        assert name not in cdef, name


ECC_SUBSETS = ("ECC_SIGN", "ECC_VERIFY", "ECC_DHE", "ECC_KEY_IMPORT", "ECC_KEY_EXPORT")
ECC_OPS = {
    "ECC_SIGN": ("wc_ecc_sign_hash(", "wc_ecc_sign_hash_ex("),
    "ECC_VERIFY": ("wc_ecc_verify_hash(", "wc_ecc_verify_hash_ex("),
    "ECC_DHE": ("wc_ecc_shared_secret(",),
    "ECC_KEY_IMPORT": ("wc_EccPrivateKeyDecode(", "wc_EccPublicKeyDecode(", "wc_ecc_import_x963(",
                       "wc_ecc_import_unsigned("),
    "ECC_KEY_EXPORT": ("wc_EccKeyToDer(", "wc_EccKeyDerSize(", "wc_EccPublicKeyToDer(",
                       "wc_ecc_export_x963(", "wc_ecc_export_private_raw(", "wc_ecc_export_public_raw("),
}
ECC_COMMON = ("ecc_key;", "wc_ecc_init(", "wc_ecc_free(", "wc_ecc_make_key(", "wc_ecc_size(",
              "wc_ecc_sig_size(", "wc_ecc_get_curve_size_from_id(", "wc_ecc_check_key(")


@pytest.mark.parametrize(("defines", "disabled"), [
    ((), ()),
    (("#define NO_ECC_SIGN",), ("ECC_SIGN",)),
    (("  #define NO_ECC_SIGN 1",), ("ECC_SIGN",)),
    (("#define NO_ECC_VERIFY",), ("ECC_VERIFY",)),
    (("#define NO_ECC_DHE",), ("ECC_DHE",)),
    (("#define NO_ECC_KEY_IMPORT",), ("ECC_KEY_IMPORT",)),
    (("#define NO_ECC_KEY_EXPORT",), ("ECC_KEY_EXPORT",)),
    # settings.h: key export needs WOLFSSL_SP_MATH or big integer math.
    (("#define NO_BIG_INT",), ("ECC_KEY_EXPORT",)),
    (("#define NO_BIG_INT", "#define WOLFSSL_SP_MATH"), ()),
    # settings.h: DHE and timing resistant signing need the RNG.
    (("#define WC_NO_RNG",), ("ECC_DHE",)),
    (("#define WC_NO_RNG", "#define ECC_TIMING_RESISTANT"), ("ECC_SIGN", "ECC_DHE")),
    (("#define NO_ECC_SIGN", "#define NO_ECC_DHE"), ("ECC_SIGN", "ECC_DHE")),
], ids=["default", "no-sign", "no-sign-indented", "no-verify", "no-dhe", "no-import", "no-export",
        "no-big-int", "no-big-int-sp-math", "no-rng", "no-rng-timing-resistant", "no-sign-no-dhe"])
def test_ecc_operations_follow_subset_macros(bf, defines, disabled):
    features = detect(bf, "#define HAVE_ECC", "#define WOLFSSL_PUBLIC_MP", *defines)
    assert features["ECC"] == 1
    for name in ECC_SUBSETS:
        assert features[name] == (name not in disabled), name
    cdef = cdef_for(bf, features)
    for subset, names in ECC_OPS.items():
        for name in names:
            assert (name in cdef) == (subset not in disabled), name
    for name in ECC_COMMON:
        assert name in cdef, name


def test_ecc_subsets_need_ecc(bf):
    features = detect(bf, "#define WOLFSSL_PUBLIC_MP")
    assert features["ECC"] == 0
    for name in ECC_SUBSETS:
        assert features[name] == 0, name
    cdef = cdef_for(bf, features)
    for names in ECC_OPS.values():
        for name in names:
            assert name not in cdef, name


ED25519_SUBSETS = ("ED25519_MAKE_KEY", "ED25519_SIGN", "ED25519_VERIFY", "ED25519_KEY_IMPORT",
                   "ED25519_KEY_EXPORT")
ED25519_OPS = {
    "ED25519_MAKE_KEY": ("wc_ed25519_make_key(", "wc_ed25519_make_public("),
    "ED25519_SIGN": ("wc_ed25519_sign_msg(",),
    "ED25519_VERIFY": ("wc_ed25519_verify_msg(",),
    "ED25519_KEY_IMPORT": ("wc_Ed25519PrivateKeyDecode(", "wc_Ed25519PublicKeyDecode(",
                           "wc_ed25519_import_public(", "wc_ed25519_import_private_only(",
                           "wc_ed25519_import_private_key("),
    "ED25519_KEY_EXPORT": ("wc_Ed25519KeyToDer(", "wc_Ed25519PublicKeyToDer(", "wc_ed25519_export_public(",
                           "wc_ed25519_export_private_only(", "wc_ed25519_export_private(",
                           "wc_ed25519_export_key("),
}
ED25519_COMMON = ("ed25519_key;", "wc_ed25519_init(", "wc_ed25519_free(", "wc_ed25519_size(",
                  "wc_ed25519_sig_size(", "wc_ed25519_check_key(", "wc_ed25519_pub_size(",
                  "wc_ed25519_priv_size(")


@pytest.mark.parametrize(("defines", "disabled"), [
    ((), ()),
    (("#define NO_ED25519_SIGN", "#define NO_ED25519_MAKE_KEY"), ("ED25519_SIGN", "ED25519_MAKE_KEY")),
    (("#define NO_ED25519_SIGN",), ("ED25519_SIGN",)),
    (("  #define NO_ED25519_SIGN 1",), ("ED25519_SIGN",)),
    (("#define NO_ED25519_VERIFY",), ("ED25519_VERIFY",)),
    (("#define NO_ED25519_KEY_IMPORT",), ("ED25519_KEY_IMPORT",)),
    (("#define NO_ED25519_KEY_EXPORT",), ("ED25519_KEY_EXPORT",)),
], ids=["default", "no-sign-no-make-key", "no-sign", "no-sign-indented", "no-verify", "no-import",
        "no-export"])
def test_ed25519_operations_follow_subset_macros(bf, defines, disabled):
    features = detect(bf, "#define HAVE_ED25519", *defines)
    assert features["ED25519"] == 1
    for name in ED25519_SUBSETS:
        assert features[name] == (name not in disabled), name
    cdef = cdef_for(bf, features)
    for subset, names in ED25519_OPS.items():
        for name in names:
            assert (name in cdef) == (subset not in disabled), name
    for name in ED25519_COMMON:
        assert name in cdef, name


def test_ed25519_subsets_need_ed25519(bf):
    features = detect(bf)
    assert features["ED25519"] == 0
    for name in ED25519_SUBSETS:
        assert features[name] == 0, name
    cdef = cdef_for(bf, features)
    for names in ED25519_OPS.values():
        for name in names:
            assert name not in cdef, name


ED448_SUBSETS = ("ED448_SIGN", "ED448_VERIFY", "ED448_KEY_IMPORT", "ED448_KEY_EXPORT")
ED448_OPS = {
    "ED448_SIGN": ("wc_ed448_sign_msg(",),
    "ED448_VERIFY": ("wc_ed448_verify_msg(",),
    "ED448_KEY_IMPORT": ("wc_Ed448PrivateKeyDecode(", "wc_Ed448PublicKeyDecode(", "wc_ed448_import_public(",
                         "wc_ed448_import_private_only(", "wc_ed448_import_private_key("),
    "ED448_KEY_EXPORT": ("wc_Ed448KeyToDer(", "wc_Ed448PublicKeyToDer(", "wc_ed448_export_public(",
                         "wc_ed448_export_private_only(", "wc_ed448_export_private(", "wc_ed448_export_key("),
}
# wolfSSL builds Ed448 key generation unconditionally.
ED448_COMMON = ("ed448_key;", "wc_ed448_init(", "wc_ed448_free(", "wc_ed448_make_key(", "wc_ed448_make_public(",
                "wc_ed448_size(", "wc_ed448_sig_size(", "wc_ed448_check_key(", "wc_ed448_pub_size(",
                "wc_ed448_priv_size(")


@pytest.mark.parametrize(("defines", "disabled"), [
    ((), ()),
    (("#define NO_ED448_SIGN",), ("ED448_SIGN",)),
    (("  #define NO_ED448_SIGN 1",), ("ED448_SIGN",)),
    (("#define NO_ED448_VERIFY",), ("ED448_VERIFY",)),
    (("#define NO_ED448_KEY_IMPORT",), ("ED448_KEY_IMPORT",)),
    (("#define NO_ED448_KEY_EXPORT",), ("ED448_KEY_EXPORT",)),
    (("#define NO_ED448_SIGN", "#define NO_ED448_KEY_EXPORT"), ("ED448_SIGN", "ED448_KEY_EXPORT")),
], ids=["default", "no-sign", "no-sign-indented", "no-verify", "no-import", "no-export", "no-sign-no-export"])
def test_ed448_operations_follow_subset_macros(bf, defines, disabled):
    features = detect(bf, "#define HAVE_ED448", *defines)
    assert features["ED448"] == 1
    for name in ED448_SUBSETS:
        assert features[name] == (name not in disabled), name
    cdef = cdef_for(bf, features)
    for subset, names in ED448_OPS.items():
        for name in names:
            assert (name in cdef) == (subset not in disabled), name
    for name in ED448_COMMON:
        assert name in cdef, name


def test_ed448_subsets_need_ed448(bf):
    features = detect(bf)
    assert features["ED448"] == 0
    for name in ED448_SUBSETS:
        assert features[name] == 0, name
    cdef = cdef_for(bf, features)
    for names in ED448_OPS.values():
        for name in names:
            assert name not in cdef, name


ML_KEM_SUBSETS = ("ML_KEM_MAKE_KEY", "ML_KEM_ENCAPSULATE", "ML_KEM_DECAPSULATE")
ML_KEM_OPS = {
    "ML_KEM_MAKE_KEY": ("wc_KyberKey_MakeKey(", "wc_KyberKey_MakeKeyWithRandom("),
    "ML_KEM_ENCAPSULATE": ("wc_KyberKey_Encapsulate(", "wc_KyberKey_EncapsulateWithRandom("),
    "ML_KEM_DECAPSULATE": ("wc_KyberKey_Decapsulate(",),
}
# wolfSSL builds key setup, sizes and encoding for every operation subset.
ML_KEM_COMMON = ("KyberKey;", "wc_KyberKey_Init(", "wc_KyberKey_Free(", "wc_KyberKey_CipherTextSize(",
                 "wc_KyberKey_SharedSecretSize(", "wc_KyberKey_PrivateKeySize(", "wc_KyberKey_PublicKeySize(",
                 "wc_KyberKey_EncodePublicKey(", "wc_KyberKey_DecodePublicKey(", "wc_KyberKey_EncodePrivateKey(",
                 "wc_KyberKey_DecodePrivateKey(")


@pytest.mark.parametrize(("defines", "disabled"), [
    ((), ()),
    (("#define WOLFSSL_MLKEM_NO_MAKE_KEY",), ("ML_KEM_MAKE_KEY",)),
    (("  #define WOLFSSL_MLKEM_NO_MAKE_KEY 1",), ("ML_KEM_MAKE_KEY",)),
    (("#define WOLFSSL_MLKEM_NO_ENCAPSULATE",), ("ML_KEM_ENCAPSULATE",)),
    (("#define WOLFSSL_MLKEM_NO_DECAPSULATE",), ("ML_KEM_DECAPSULATE",)),
    (("#define WOLFSSL_KYBER_NO_MAKE_KEY",), ("ML_KEM_MAKE_KEY",)),
    (("#define WOLFSSL_KYBER_NO_ENCAPSULATE",), ("ML_KEM_ENCAPSULATE",)),
    (("#define WOLFSSL_KYBER_NO_DECAPSULATE",), ("ML_KEM_DECAPSULATE",)),
    (("#define WOLFSSL_MLKEM_NO_MAKE_KEY", "#define WOLFSSL_MLKEM_NO_DECAPSULATE"),
     ("ML_KEM_MAKE_KEY", "ML_KEM_DECAPSULATE")),
], ids=["default", "no-make-key", "no-make-key-indented", "no-encapsulate", "no-decapsulate",
        "legacy-no-make-key", "legacy-no-encapsulate", "legacy-no-decapsulate", "encapsulate-only"])
def test_ml_kem_operations_follow_subset_macros(bf, defines, disabled):
    features = detect(bf, "#define WOLFSSL_HAVE_MLKEM", *defines)
    assert features["ML_KEM"] == 1
    for name in ML_KEM_SUBSETS:
        assert features[name] == (name not in disabled), name
    cdef = cdef_for(bf, features)
    for subset, names in ML_KEM_OPS.items():
        for name in names:
            assert (name in cdef) == (subset not in disabled), name
    for name in ML_KEM_COMMON:
        assert name in cdef, name


def test_ml_kem_subsets_need_ml_kem(bf):
    features = detect(bf)
    assert features["ML_KEM"] == 0
    for name in ML_KEM_SUBSETS:
        assert features[name] == 0, name
    cdef = cdef_for(bf, features)
    for names in ML_KEM_OPS.values():
        for name in names:
            assert name not in cdef, name


ML_DSA_SUBSETS = ("ML_DSA_MAKE_KEY", "ML_DSA_SIGN", "ML_DSA_VERIFY", "ML_DSA_PUBLIC_KEY", "ML_DSA_PRIVATE_KEY")
# Function -> sub-capabilities that must all be enabled for it.
ML_DSA_OPS = {
    "wc_dilithium_make_key(": ("ML_DSA_MAKE_KEY",),
    "wc_dilithium_make_key_from_seed(": ("ML_DSA_MAKE_KEY",),
    "wc_dilithium_export_public(": ("ML_DSA_PUBLIC_KEY",),
    "wc_dilithium_import_public(": ("ML_DSA_PUBLIC_KEY",),
    "wc_MlDsaKey_GetPubLen(": ("ML_DSA_PUBLIC_KEY",),
    "wc_dilithium_export_private(": ("ML_DSA_PRIVATE_KEY",),
    "wc_dilithium_import_private(": ("ML_DSA_PRIVATE_KEY",),
    "wc_MlDsaKey_GetPrivLen(": ("ML_DSA_PRIVATE_KEY", "ML_DSA_PUBLIC_KEY"),
    "wc_dilithium_sign_ctx_msg(": ("ML_DSA_SIGN",),
    "wc_dilithium_sign_ctx_msg_with_seed(": ("ML_DSA_SIGN",),
    "wc_dilithium_verify_ctx_msg(": ("ML_DSA_VERIFY",),
}
ML_DSA_COMMON = ("dilithium_key;", "wc_dilithium_init_ex(", "wc_dilithium_set_level(", "wc_dilithium_free(",
                 "DILITHIUM_SEED_SZ;", "WC_ML_DSA_44;")
MLDSA_VERIFY_ONLY = ("ML_DSA_MAKE_KEY", "ML_DSA_SIGN", "ML_DSA_PRIVATE_KEY")


@pytest.mark.parametrize(("defines", "disabled"), [
    ((), ()),
    (("#define WOLFSSL_MLDSA_VERIFY_ONLY",), MLDSA_VERIFY_ONLY),
    (("  #define WOLFSSL_MLDSA_VERIFY_ONLY 1",), MLDSA_VERIFY_ONLY),
    (("#define WOLFSSL_MLDSA_VERIFY_ONLY", "#define WOLFSSL_MLDSA_NO_MAKE_KEY", "#define WOLFSSL_MLDSA_NO_SIGN"),
     MLDSA_VERIFY_ONLY),
    (("#define WOLFSSL_MLDSA_NO_MAKE_KEY", "#define WOLFSSL_MLDSA_NO_SIGN"), MLDSA_VERIFY_ONLY),
    (("#define WOLFSSL_DILITHIUM_VERIFY_ONLY",), MLDSA_VERIFY_ONLY),
    (("#define WOLFSSL_MLDSA_NO_MAKE_KEY",), ("ML_DSA_MAKE_KEY",)),
    (("#define WOLFSSL_MLDSA_NO_SIGN",), ("ML_DSA_SIGN",)),
    (("#define WOLFSSL_DILITHIUM_NO_SIGN",), ("ML_DSA_SIGN",)),
    (("#define WOLFSSL_MLDSA_NO_VERIFY",), ("ML_DSA_VERIFY",)),
    (("#define WOLFSSL_DILITHIUM_NO_VERIFY",), ("ML_DSA_VERIFY",)),
    (("#define WOLFSSL_MLDSA_NO_MAKE_KEY", "#define WOLFSSL_MLDSA_NO_VERIFY"),
     ("ML_DSA_MAKE_KEY", "ML_DSA_VERIFY", "ML_DSA_PUBLIC_KEY")),
    (("#define WOLFSSL_MLDSA_NO_MAKE_KEY", "#define WOLFSSL_MLDSA_NO_VERIFY", "#define WOLFSSL_MLDSA_PUBLIC_KEY"),
     ("ML_DSA_MAKE_KEY", "ML_DSA_VERIFY")),
    (("#define WOLFSSL_MLDSA_VERIFY_ONLY", "#define WOLFSSL_DILITHIUM_PRIVATE_KEY"),
     ("ML_DSA_MAKE_KEY", "ML_DSA_SIGN")),
], ids=["default", "verify-only", "verify-only-indented", "verify-only-configure", "verify-only-derived",
        "legacy-verify-only", "no-make-key", "no-sign", "legacy-no-sign", "no-verify", "legacy-no-verify",
        "sign-only", "sign-only-public-key", "verify-only-private-key"])
@pytest.mark.parametrize("parent", ["#define WOLFSSL_HAVE_MLDSA", "#define HAVE_DILITHIUM"])
def test_ml_dsa_operations_follow_subset_macros(bf, parent, defines, disabled):
    features = detect(bf, parent, *defines)
    assert features["ML_DSA"] == 1
    for name in ML_DSA_SUBSETS:
        assert features[name] == (name not in disabled), name
    cdef = cdef_for(bf, features)
    for name, needs in ML_DSA_OPS.items():
        assert (name in cdef) == all(features[n] for n in needs), name
    assert ("wc_MlDsaKey_GetSigLen(" in cdef) == bool(features["ML_DSA_SIGN"] or features["ML_DSA_VERIFY"])
    for name in ML_DSA_COMMON:
        assert name in cdef, name


@pytest.mark.parametrize(("defines", "sign", "verify"), [
    ((), True, True),
    (("#define WOLFSSL_MLDSA_VERIFY_ONLY",), False, True),
    (("#define WOLFSSL_MLDSA_NO_VERIFY",), True, False),
], ids=["default", "verify-only", "no-verify"])
def test_ml_dsa_no_ctx_operations_follow_subset_macros(bf, defines, sign, verify):
    features = detect(bf, "#define WOLFSSL_MLDSA_NO_CTX", "#define WOLFSSL_HAVE_MLDSA", *defines)
    assert features["ML_DSA_NO_CTX"] == 1
    cdef = cdef_for(bf, features)
    assert ("wc_dilithium_sign_msg(" in cdef) == sign
    assert ("wc_dilithium_sign_msg_with_seed(" in cdef) == sign
    assert ("wc_dilithium_verify_msg(" in cdef) == verify


def test_ml_dsa_subsets_need_ml_dsa(bf):
    features = detect(bf)
    assert features["ML_DSA"] == 0
    for name in ML_DSA_SUBSETS:
        assert features[name] == 0, name
    cdef = cdef_for(bf, features)
    for name in (*ML_DSA_OPS, "wc_MlDsaKey_GetSigLen("):
        assert name not in cdef, name
