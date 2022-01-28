#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

import os
import sys
import subprocess
from contextlib import contextmanager
from distutils.util import get_platform
from wolfcrypt.__init__ import __wolfssl_version__ as version


def local_path(path):
    """ Return path relative to the root of this project
    """
    current = os.path.abspath(os.getcwd())
    return os.path.abspath(os.path.join(current, path))

WOLFSSL_SRC_PATH = local_path("lib/wolfssl")


def wolfssl_inc_path():
    if sys.platform == "win32":
        return os.path.join(WOLFSSL_SRC_PATH)
    else:
        wolfssl_path = os.environ.get("USE_LOCAL_WOLFSSL")
        if wolfssl_path is None:
            return local_path("lib/wolfssl")
        else:
            if os.path.isdir(wolfssl_path) and os.path.exists(wolfssl_path):
                return wolfssl_path + "/include"
            else:
                return "/usr/local/include"


def wolfssl_lib_path():
    if sys.platform == "win32":
        return os.path.join(WOLFSSL_SRC_PATH, "build", "Release")
    else:
        wolfssl_path = os.environ.get("USE_LOCAL_WOLFSSL")
        if wolfssl_path is None:
            return local_path("lib/wolfssl/{}/{}/lib".format(
                              get_platform(), version))
        else:
            if os.path.isdir(wolfssl_path) and os.path.exists(wolfssl_path):
                return wolfssl_path + "/lib"
            else:
                return "/usr/local/lib"


def call(cmd):
    print("Calling: '{}' from working directory {}".format(cmd, os.getcwd()))

    old_env = os.environ["PATH"]
    os.environ["PATH"] = "{}:{}".format(WOLFSSL_SRC_PATH, old_env)
    subprocess.check_call(cmd, shell=True, env=os.environ)
    os.environ["PATH"] = old_env


@contextmanager
def chdir(new_path, mkdir=False):
    old_path = os.getcwd()

    if mkdir:
        try:
            os.mkdir(new_path)
        except OSError:
            pass

    try:
        yield os.chdir(new_path)
    finally:
        os.chdir(old_path)


def checkout_version(version):
    """ Ensure that we have the right version
    """
    with chdir(WOLFSSL_SRC_PATH):
        current = ""
        try:
            current = subprocess.check_output(
                ["git", "describe", "--all", "--exact-match"]
            ).strip().decode().split('/')[-1]
        except:
            pass

        if current != version:
            tags = subprocess.check_output(
                ["git", "tag"]
            ).strip().decode().split("\n")

            if version != "master" and version not in tags:
                call("git fetch --depth=1 origin tag {}".format(version))

            call("git checkout --force {}".format(version))

            return True  # rebuild needed

    return False


def ensure_wolfssl_src(ref):
    """ Ensure that wolfssl sources are presents and up-to-date
    """
    if not os.path.isdir("lib"):
        os.mkdir("lib")
        with chdir("lib"):
            subprocess.run(["git", "clone", "--depth=1", "https://github.com/wolfssl/wolfssl"])

    if not os.path.isdir(os.path.join(WOLFSSL_SRC_PATH, "wolfssl")):
        subprocess.run(["git", "submodule", "update", "--init", "--depth=1"])

    return checkout_version(version)


def make_flags(prefix):
    """ Returns compilation flags
    """
    if sys.platform == "win32":
        flags = []
        flags.append("-DWOLFSSL_CRYPT_TESTS=no")
        flags.append("-DWOLFSSL_EXAMPLES=no")
        flags.append("-DBUILD_SHARED_LIBS=off")
        flags.append("-DWOLFSSL_CRYPT_ONLY=yes")
        flags.append("-DWOLFSSL_AES=yes")
        flags.append("-DWOLFSSL_DES3=yes")
        flags.append("-DWOLFSSL_CHACHA=yes")
        flags.append("-DWOLFSSL_AESGCM=no")
        flags.append("-DWOLFSSL_SHA=yes")
        flags.append("-DWOLFSSL_SHA384=yes")
        flags.append("-DWOLFSSL_SHA512=yes")
        flags.append("-DWOLFSSL_SHA3=yes")
        flags.append("-DWOLFSSL_HKDF=yes")
        flags.append("-DWOLFSSL_MD5=no")
        flags.append("-DWOLFSSL_SHA224=no")
        flags.append("-DWOLFSSL_POLY1305=no")
        flags.append("-DWOLFSSL_RSA=yes")
        flags.append("-DWOLFSSL_ECC=yes")
        flags.append("-DWOLFSSL_ED25519=yes")
        flags.append("-DWOLFSSL_ED448=yes")
        flags.append("-DWOLFSSL_CURVE25519=yes")
        flags.append("-DWOLFSSL_DH=no")
        flags.append("-DWOLFSSL_PWDBASED=yes")
        flags.append("-DWOLFSSL_PKCS7=yes")
        flags.append("-DWOLFSSL_OLD_TLS=no")
        flags.append("-DWOLFSSL_OLD_NAMES=no")
        flags.append("-DWOLFSSL_EXTENDED_MASTER=no")
        flags.append("-DWOLFSSL_ERROR_STRINGS=no")
        # Part of hack for missing CMake option
        flags.append("-DCMAKE_C_FLAGS=\"/DWOLFSSL_KEY_GEN=1 /DWOLFCRYPT_ONLY=1\"")

        return " ".join(flags)
    else:
        flags = []

        if get_platform() in ["linux-x86_64", "linux-i686"]:
            flags.append("CFLAGS=-fPIC")

        # install location
        flags.append("--prefix={}".format(prefix))

        # crypt only, lib only
        flags.append("--enable-cryptonly")
        flags.append("--disable-crypttests")
        flags.append("--disable-shared")

        # symmetric ciphers
        flags.append("--enable-aes")
        flags.append("--enable-aesctr")
        flags.append("--enable-des3")
        flags.append("--enable-chacha")

        flags.append("--disable-aesgcm")

        # hashes and MACs
        flags.append("--enable-sha")
        flags.append("--enable-sha384")
        flags.append("--enable-sha512")
        flags.append("--enable-sha3")
        flags.append("--enable-hkdf")

        flags.append("--disable-md5")
        flags.append("--disable-sha224")
        flags.append("--disable-poly1305")

        # asymmetric ciphers
        flags.append("--enable-rsa")
        flags.append("--enable-ecc")
        flags.append("--enable-ed25519")
        flags.append("--enable-ed448")
        flags.append("--enable-curve25519")
        flags.append("--enable-keygen")

        flags.append("--disable-dh")

        # pwdbased
        flags.append("--enable-pwdbased")
        flags.append("--enable-pkcs7")

        # disabling other configs enabled by default
        flags.append("--disable-oldtls")
        flags.append("--disable-oldnames")
        flags.append("--disable-extended-master")
        flags.append("--disable-errorstrings")

        return " ".join(flags)


# Horrid hack because we have no CMake option in 5.1.1 for this
def cmake_hack():
    options_file = os.path.join(WOLFSSL_SRC_PATH, "wolfssl", "options.h")
    with open(options_file, "r") as f:
        contents = f.readlines()

    contents.insert(26, "#undef WOLFSSL_KEY_GEN\n")
    contents.insert(27, "#define WOLFSSL_KEY_GEN\n")
    contents.insert(28, "#undef WOLFCRYPT_ONLY\n")
    contents.insert(29, "#define WOLFCRYPT_ONLY\n")

    with open(options_file, "w") as f:
        contents = "".join(contents)
        f.write(contents)


def make(configure_flags):
    """ Create a release of wolfSSL C library
    """
    if sys.platform == 'win32':
        build_path = os.path.join(WOLFSSL_SRC_PATH, "build")
        if not os.path.isdir(build_path):
            os.mkdir(build_path)
        with chdir(build_path):
            call("cmake .. {}".format(configure_flags))
            cmake_hack()
            call("cmake --build . --config Release")
    else:
        with chdir(WOLFSSL_SRC_PATH):
            call("git clean -fdX")

            try:
                call("./autogen.sh")
            except subprocess.CalledProcessError:
                call("libtoolize")
                call("./autogen.sh")

            call("./configure {}".format(configure_flags))
            call("make")
            call("make install-exec")


def build_wolfssl(version="master"):
    prefix = local_path("lib/wolfssl/{}/{}".format(
        get_platform(), version))
    if sys.platform == 'win32':
        libfile = os.path.join(WOLFSSL_SRC_PATH, "build", "Release", "wolfssl.lib")
    else:
        libfile = os.path.join(prefix, 'lib/libwolfssl.la')

    rebuild = ensure_wolfssl_src(version)

    if rebuild or not os.path.isfile(libfile):
        make(make_flags(prefix))

if __name__ == "__main__":
    build_wolfssl()
