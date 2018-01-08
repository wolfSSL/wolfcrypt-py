# test_hashes.py
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

# pylint: disable=redefined-outer-name

from collections import namedtuple
import pytest
from wolfcrypt.utils import t2b
from wolfcrypt.hashes import (
    Sha, Sha256, Sha384, Sha512, HmacSha, HmacSha256, HmacSha384, HmacSha512
)


@pytest.fixture
def vectors():
    TestVector = namedtuple("TestVector", "digest")
    TestVector.__new__.__defaults__ = (None,) * len(TestVector._fields)

    return {
        Sha: TestVector(
            digest=t2b("1b6182d68ae91ce0853bd9c6b6edfedd4b6a510d")
        ),
        Sha256: TestVector(
            digest=t2b("96e02e7b1cbcd6f104fe1fdb4652027a" +
                       "5505b68652b70095c6318f9dce0d1844")
        ),
        Sha384: TestVector(
            digest=t2b("4c79d80531203a16f91bee325f18c6aada47f9382fe44fc1" +
                       "1f92917837e9b7902f5dccb7d3656f667a1dce3460bc884b")
        ),
        Sha512: TestVector(
            digest=t2b("88fcf67ffd8558d713f9cedcd852db47" +
                       "9e6573f0bd9955610a993f609637553c" +
                       "e8fff55e644ee8a106aae19c07f91b3f" +
                       "2a2a6d40dfa7302c0fa6a1a9a5bfa03f")
        ),
        HmacSha: TestVector(
            digest=t2b("5dfabcfb3a25540824867cd21f065f52f73491e0")
        ),
        HmacSha256: TestVector(
            digest=t2b("4b641d721493d80f019d9447830ebfee" +
                       "89234a7d594378b89f8bb73873576bf6")
        ),
        HmacSha384: TestVector(
            digest=t2b("e72c72070c9c5c78e3286593068a510c1740cdf9dc34b512" +
                       "ccec97320295db1fe673216b46fe72e81f399a9ec04780ab")
        ),
        HmacSha512: TestVector(
            digest=t2b("c7f48db79314fc2b5be9a93fd58601a1" +
                       "bf42f397ec7f66dba034d44503890e6b" +
                       "5708242dcd71a248a78162d815c685f6" +
                       "038a4ac8cb34b8bf18986dbd300c9b41")
        ),
    }


@pytest.fixture(params=[
    Sha, Sha256, Sha384, Sha512, HmacSha, HmacSha256, HmacSha384, HmacSha512])
def hash_cls(request):
    return request.param


def hash_new(cls, data=None):
    if cls in [Sha, Sha256, Sha384, Sha512]:
        return cls(data)

    return cls("python", data)


def test_hash(hash_cls, vectors):
    digest = vectors[hash_cls].digest

    # update inside constructor
    assert hash_new(hash_cls, "wolfcrypt").hexdigest() == digest

    # single update
    hash_obj = hash_new(hash_cls)
    hash_obj.update("wolfcrypt")

    assert hash_obj.hexdigest() == digest

    # many updates
    hash_obj = hash_new(hash_cls)
    hash_obj.update("wolf")
    hash_obj.update("crypt")

    assert hash_obj.hexdigest() == digest

    # copy
    hash_obj = hash_new(hash_cls)
    copy = hash_obj.copy()

    assert hash_obj.hexdigest() == copy.hexdigest()

    hash_obj.update("wolfcrypt")

    assert hash_obj.hexdigest() != copy.hexdigest()

    copy.update("wolfcrypt")

    assert hash_obj.hexdigest() == copy.hexdigest() == digest
