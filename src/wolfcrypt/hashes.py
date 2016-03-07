# hashes.py
#
# Copyright (C) 2006-2016 wolfSSL Inc.
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


class Hash(object):
    _JAPANESE_CYBER_SWORD = object()


    def __init__(self, token=""):
        if token is not self._JAPANESE_CYBER_SWORD:
            # PEP 247 -- API for Cryptographic Hash Functions
            raise ValueError("don't construct directly, use new([string])")


    @classmethod
    def new(cls):
        return cls(cls._JAPANESE_CYBER_SWORD)


class Sha(Hash):
    digest_size = 20


    @classmethod
    def new(cls, string=None):
        obj = Hash.new()

        obj.digest_size = cls.digest_size

        if (string):
            obj.update(string)

        return obj


    def copy(self):
        pass


    def update(self, string):
        pass


    def digest(self):
        pass


    def hexdigest(self):
        pass


class Sha256(Hash):
    digest_size = 32


    @classmethod
    def new(cls, string=None):
        obj = Hash.new()

        obj.digest_size = cls.digest_size

        if (string):
            obj.update(string)

        return obj


    def copy(self):
        pass


    def update(self, string):
        pass


    def digest(self):
        pass


    def hexdigest(self):
        pass


class Sha384(Hash):
    digest_size = 48

    @classmethod
    def new(cls, string=None):
        obj = Hash.new()

        obj.digest_size = cls.digest_size

        if (string):
            obj.update(string)

        return obj


    def copy(self):
        pass


    def update(self, string):
        pass


    def digest(self):
        pass


    def hexdigest(self):
        pass


class Sha512(Hash):
    digest_size = 64

    @classmethod
    def new(cls, string=None):
        obj = Hash.new()

        obj.digest_size = cls.digest_size

        if (string):
            obj.update(string)

        return obj


    def copy(self):
        pass


    def update(self, string):
        pass


    def digest(self):
        pass


    def hexdigest(self):
        pass
