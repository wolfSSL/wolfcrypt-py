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

# pylint: disable=wrong-import-position

import os
import sys
from setuptools import setup, find_packages

os.chdir(os.path.dirname(sys.argv[0]) or ".")

import re
VERSIONFILE = "wolfcrypt/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))
VSRE = r"^__wolfssl_version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    wolfverstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))


# long_description
with open("README.rst") as readme_file:
    long_description = readme_file.read()

with open("LICENSING.rst") as licensing_file:
    long_description = long_description.replace(".. include:: LICENSING.rst\n",
                                                licensing_file.read())

setup(
    name="wolfcrypt",
    version=verstr,
    description="Python module that encapsulates wolfSSL's crypto engine API.",
    long_description=long_description,
    long_description_content_type='text/x-rst',
    author="wolfSSL Inc.",
    author_email="info@wolfssl.com",
    url="https://github.com/wolfssl/wolfcrypt-py",
    license="GPLv2 or Commercial License",

    packages=find_packages(),
    keywords="wolfssl, wolfcrypt, security, cryptography",
    classifiers=[
        u"License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        u"License :: Other/Proprietary License",
        u"Operating System :: OS Independent",
        u"Programming Language :: Python :: 3",
        u"Programming Language :: Python :: 3.6",
        u"Programming Language :: Python :: 3.7",
        u"Programming Language :: Python :: 3.8",
        u"Programming Language :: Python :: 3.9",
        u"Topic :: Security",
        u"Topic :: Security :: Cryptography",
        u"Topic :: Software Development"
    ],

    setup_requires=["cffi>=1.0.0"],
    install_requires=["cffi>=1.0.0"],
    cffi_modules=["./scripts/build_ffi.py:ffibuilder"],

    package_data={"wolfcrypt": ["*.dll"]}
)
