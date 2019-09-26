# __init__.py
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

__title__ = "wolfcrypt"
__summary__ = "Python module that encapsulates wolfSSL's crypto engine API."
__uri__ = "https://github.com/wolfssl/wolfcrypt-py"

# When bumping the C library version, reset the POST count to 0

__wolfssl_version__ = "v4.1.0-stable"

# We're using implicit post releases [PEP 440] to bump package version
# while maintaining the C library version intact for better reference.
# https://www.python.org/dev/peps/pep-0440/#implicit-post-releases
#
# MAJOR.MINOR.BUILD-POST

__version__ = "4.1.0-0"

__author__ = "wolfSSL Inc."
__email__ = "info@wolfssl.com"

__license__ = "GPLv2 or Commercial License"
__copyright__ = "Copyright (C) 2006-2018 wolfSSL Inc"

__all__ = [
    "__title__", "__summary__", "__uri__", "__version__",
    "__author__", "__email__", "__license__", "__copyright__",
    "ciphers", "hashes", "random"
]
