#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

# pylint: disable=wrong-import-position

import os
import sys
from setuptools import setup
from setuptools.command.build_ext import build_ext


# Adding src folder to the include path in order to import from wolfcrypt
package_dir = os.path.join(os.path.dirname(__file__), "src")
sys.path.insert(0, package_dir)

import wolfcrypt
from wolfcrypt._build_wolfssl import build_wolfssl


# long_description
with open("README.rst") as readme_file:
    long_description = readme_file.read()

with open("LICENSING.rst") as licensing_file:
    long_description = long_description.replace(".. include:: LICENSING.rst\n",
                                                licensing_file.read())


class cffiBuilder(build_ext, object):

    def build_extension(self, ext):
        """ Compile manually the wolfcrypt-py extension, bypass setuptools
        """

        # if USE_LOCAL_WOLFSSL environment variable has been defined,
        # do not clone and compile wolfSSL from GitHub
        if os.environ.get("USE_LOCAL_WOLFSSL") is None:
            build_wolfssl(wolfcrypt.__wolfssl_version__)

        super(cffiBuilder, self).build_extension(ext)


setup(
    name=wolfcrypt.__title__,
    version=wolfcrypt.__version__,
    description=wolfcrypt.__summary__,
    long_description=long_description,
    author=wolfcrypt.__author__,
    author_email=wolfcrypt.__email__,
    url=wolfcrypt.__uri__,
    license=wolfcrypt.__license__,

    packages=["wolfcrypt"],
    package_dir={"":package_dir},

    zip_safe=False,
    cffi_modules=["./src/wolfcrypt/_build_ffi.py:ffibuilder"],

    keywords="wolfssl, wolfcrypt, security, cryptography",
    classifiers=[
        u"License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        u"License :: Other/Proprietary License",
        u"Operating System :: OS Independent",
        u"Programming Language :: Python :: 2.7",
        u"Programming Language :: Python :: 3.4",
        u"Programming Language :: Python :: 3.5",
        u"Programming Language :: Python :: 3.6",
        u"Topic :: Security",
        u"Topic :: Security :: Cryptography",
        u"Topic :: Software Development"
    ],

    setup_requires=["cffi"],
    install_requires=["cffi"],
    cmdclass={"build_ext" : cffiBuilder}
)
