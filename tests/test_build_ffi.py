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
