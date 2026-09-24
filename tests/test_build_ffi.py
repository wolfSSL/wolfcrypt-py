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
