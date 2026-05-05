# test_delete_descriptor_binding.py
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

"""
Regression tests guarding against the Python descriptor-binding bug on
``_delete`` / ``_copy`` class attributes.

Historically these were written as bare references to ``_lib`` functions::

    class Random:
        _delete = _lib.wc_FreeRng

        def __del__(self):
            self._delete(self.native_object)

If the underlying callable is ever a plain Python function (e.g. a mock,
wrapper, or future CFFI change), the descriptor protocol turns
``self._delete`` into a *bound method*, and ``self._delete(native)`` then
calls ``fn(self, native)`` - passing ``self`` as an extra C argument.

The fix wraps the callable in ``staticmethod(...)`` at the class level so
that attribute lookup never binds ``self``. These tests assert the fix
stays in place and document the Python semantics it relies on.
"""

# pylint: disable=redefined-outer-name

import inspect

import pytest

from wolfcrypt._ffi import lib as _lib


def _static_attrs():
    """Yield (cls, attr_name) pairs that must be staticmethod-wrapped."""
    from wolfcrypt.random import Random
    yield Random, "_delete"

    if _lib.SHA_ENABLED:
        from wolfcrypt.hashes import Sha
        yield Sha, "_delete"
        yield Sha, "_copy"
    if _lib.SHA256_ENABLED:
        from wolfcrypt.hashes import Sha256
        yield Sha256, "_delete"
        yield Sha256, "_copy"
    if _lib.SHA384_ENABLED:
        from wolfcrypt.hashes import Sha384
        yield Sha384, "_delete"
        yield Sha384, "_copy"
    if _lib.SHA512_ENABLED:
        from wolfcrypt.hashes import Sha512
        yield Sha512, "_delete"
        yield Sha512, "_copy"
    if _lib.HMAC_ENABLED:
        from wolfcrypt.hashes import _Hmac
        yield _Hmac, "_delete"

    if _lib.AESGCM_STREAM_ENABLED:
        from wolfcrypt.ciphers import AesGcmStream
        yield AesGcmStream, "_delete"
    if _lib.RSA_ENABLED:
        from wolfcrypt.ciphers import _Rsa
        yield _Rsa, "_delete"
    if _lib.ECC_ENABLED:
        from wolfcrypt.ciphers import _Ecc
        yield _Ecc, "_delete"
    if _lib.ED25519_ENABLED:
        from wolfcrypt.ciphers import _Ed25519
        yield _Ed25519, "_delete"
    if _lib.ED448_ENABLED:
        from wolfcrypt.ciphers import _Ed448
        yield _Ed448, "_delete"


@pytest.mark.parametrize(
    "cls,attr",
    list(_static_attrs()),
    ids=lambda v: v if isinstance(v, str) else v.__name__,
)
def test_lib_fn_class_attr_is_staticmethod(cls, attr):
    """The class attribute must be a ``staticmethod`` so that attribute
    access via an instance never triggers descriptor binding.

    ``inspect.getattr_static`` walks the MRO without invoking descriptors,
    so it returns the raw object (the ``staticmethod`` wrapper itself).
    """
    raw = inspect.getattr_static(cls, attr)
    assert isinstance(raw, staticmethod), (
        "%s.%s must be wrapped in staticmethod(...) to prevent Python's "
        "descriptor protocol from injecting `self` as an extra positional "
        "argument when the underlying callable is a plain Python function "
        "(e.g. a test mock). Got %r." % (cls.__name__, attr, type(raw))
    )


def test_descriptor_binding_semantics_documentation():
    """Document the exact Python behavior the fix relies on.

    Without ``staticmethod``, a Python-function class attribute becomes a
    bound method and leaks ``self`` into the call. ``staticmethod`` makes
    the descriptor return the underlying callable unchanged.
    """
    received = []

    def recorder(*args, **kwargs):
        received.append((args, kwargs))

    class Buggy:
        _delete = recorder

        def run(self):
            self._delete("native")

    class Fixed:
        _delete = staticmethod(recorder)

        def run(self):
            self._delete("native")

    Buggy().run()
    buggy_args, _ = received[-1]
    assert len(buggy_args) == 2 and buggy_args[1] == "native", (
        "Sanity check failed: plain class-attribute Python function "
        "should have been bound and passed self as the first arg."
    )

    Fixed().run()
    fixed_args, _ = received[-1]
    assert fixed_args == ("native",), (
        "staticmethod-wrapping should prevent self from being bound, "
        "so the callable receives only the intended positional argument."
    )


def test_random_delete_receives_only_native_object():
    """End-to-end behavioral check on the real ``Random`` class.

    We substitute a plain Python recorder in place of the CFFI free
    function (wrapped in staticmethod, mirroring how the class itself
    stores it) and trigger the code path that calls ``self._delete``.
    The recorder must see exactly one positional argument - the
    ``native_object`` - and never ``self``.
    """
    from wolfcrypt.random import Random

    received = []

    def recorder(*args, **kwargs):
        received.append((args, kwargs))

    original = inspect.getattr_static(Random, "_delete")
    try:
        Random._delete = staticmethod(recorder)
        r = Random()
        native = r.native_object
        r.__del__()
        r.native_object = None  # prevent real cleanup on the way out
        assert received, "recorder was never called"
        args, kwargs = received[-1]
        assert kwargs == {}
        assert args == (native,), (
            "Random.__del__ must call _delete with only native_object, "
            "but got args=%r" % (args,)
        )
    finally:
        Random._delete = original
