# wc_types.py
#
# Copyright (C) 2026 wolfSSL Inc.
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

from abc import abstractmethod
from typing import Protocol

from .utils import BytesOrStr


class SupportsRsaSign(Protocol):
    @abstractmethod
    def sign(self, plaintext: BytesOrStr) -> bytes:
        raise NotImplementedError

class SupportsRsaVerify(Protocol):
    @abstractmethod
    def verify(self, signature: BytesOrStr) -> bytes:
        raise NotImplementedError
