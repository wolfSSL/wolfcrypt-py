#!/usr/bin/env python
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

# pylint: disable=wrong-import-position

import os
import re
import sys
from setuptools import setup, find_packages

os.chdir(os.path.dirname(sys.argv[0]) or ".")

VERSIONFILE = "wolfcrypt/_version.py"
verstrline = open(VERSIONFILE).read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError(f"Unable to find version string in {VERSIONFILE}.")
VSRE = r"^__wolfssl_version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    wolfverstr = mo.group(1)
else:
    raise RuntimeError(f"Unable to find version string in {VERSIONFILE}.")


# long_description
with open("README.rst") as readme_file:
    long_description = readme_file.read()

with open("LICENSING.rst") as licensing_file:
    long_description = long_description.replace(".. include:: LICENSING.rst\n",
                                                licensing_file.read())

setup(
    name="wolfcrypt",
    version=verstr,
    long_description=long_description,
    long_description_content_type='text/x-rst',

    packages=find_packages(),

    setup_requires=["cffi>=1.17"],
    install_requires=["cffi>=1.17"],
    cffi_modules=["./scripts/build_ffi.py:ffibuilder"],

    package_data={"wolfcrypt": ["*.dll", "**/*.pyi"]}
)
