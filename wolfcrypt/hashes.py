# hashes.py
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

# pylint: disable=no-member,no-name-in-module, no-self-use

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.utils import t2b, b2h

from wolfcrypt.exceptions import WolfCryptApiError


class _Hash:
    """
    A **PEP 247: Cryptographic Hash Functions** compliant
    **Hash Function Interface**.
    """
    def __init__(self, string=None):
        self._native_object = _ffi.new(self._native_type)
        self._shallow_copy = False
        ret = self._init()
        if ret < 0:  # pragma: no cover
            raise WolfCryptApiError("Hash init error", ret)

        if string:
            self.update(string)

    @classmethod
    def new(cls, string=None):
        """
        Creates a new hashing object and returns it. The optional
        **string** parameter, if supplied, will be immediately
        hashed into the object's starting state, as if
        obj.update(string) was called.
        """
        return cls(string)

    def copy(self):
        """
        Returns a separate copy of this hashing object. An update
        to this copy won't affect the original object.
        """
        # Bypass __init__ to avoid calling _init() on a state that _copy
        # immediately overwrites (which would leak internal resources in
        # async/HW-accelerated builds). Mark as shallow up front so __del__
        # skips the free if we bail out before the copy completes.
        copy = type(self).__new__(type(self))
        copy._shallow_copy = True  # pylint: disable=protected-access
        copy._native_object = _ffi.new(self._native_type)  # pylint: disable=protected-access

        copy_fn = getattr(self, '_copy', None)
        if copy_fn:
            ret = copy_fn(self._native_object,
                          copy._native_object)  # pylint: disable=protected-access
            if ret < 0:  # pragma: no cover
                # Free any partial allocation before raising; __del__ would
                # skip it because _shallow_copy is still True.
                delete = getattr(self, '_delete', None)
                if delete:
                    delete(copy._native_object)  # pylint: disable=protected-access
                raise WolfCryptApiError("Hash copy error", ret)
            copy._shallow_copy = False  # pylint: disable=protected-access
        else:
            _ffi.memmove(copy._native_object,  # pylint: disable=protected-access
                         self._native_object,
                         self._native_size)
            # Keep _shallow_copy = True: memmove shares internal state with
            # self, so __del__ must not free it separately.

        return copy

    def update(self, string):
        """
        Hashes **string** into the current state of the hashing
        object. update() can be called any number of times during
        a hashing object's lifetime.
        """
        string = t2b(string)

        ret = self._update(string)
        if ret < 0:  # pragma: no cover
            raise WolfCryptApiError("Hash update error", ret)

    def digest(self):
        """
        Returns the hash value of this hashing object as a string
        containing 8-bit data. The object is not altered in any
        way by this function; you can continue updating the object
        after calling this function.
        """
        result = _ffi.new("byte[%d]" % self.digest_size)

        if self._native_object:
            obj = _ffi.new(self._native_type)
            # _copy and _delete are class attributes on Sha/Sha256/etc, but
            # are set as instance attributes on Sha3 (because the SHA3 variant
            # is selected by digest_size at __init__ time). getattr handles
            # both cases.
            copy_fn = getattr(self, '_copy', None)

            try:
                if copy_fn:
                    ret = copy_fn(self._native_object, obj)
                    if ret < 0:  # pragma: no cover
                        raise WolfCryptApiError("Hash copy error", ret)
                else:
                    _ffi.memmove(obj, self._native_object, self._native_size)

                ret = self._final(obj, result)
                if ret < 0:  # pragma: no cover
                    raise WolfCryptApiError("Hash finalize error", ret)
            finally:
                # Only free when we did a deep copy; memmove'd temps share
                # internal resources with self and must not be separately freed.
                # Runs even on failed copy to clean up any partial allocation.
                if copy_fn:
                    delete = getattr(self, '_delete', None)
                    if delete:
                        delete(obj)

        return _ffi.buffer(result, self.digest_size)[:]

    def hexdigest(self):
        """
        Returns the hash value of this hashing object as a string
        containing hexadecimal digits. Lowercase letters are used
        for the digits 'a' through 'f'. Like the .digest() method,
        this method doesn't alter the object.
        """
        return b2h(self.digest())


if _lib.SHA_ENABLED:
    class Sha(_Hash):
        """
        **SHA-1** is a cryptographic hash function standardized by **NIST**.

        It produces an [ **160-bit | 20 bytes** ] message digest.
        """
        digest_size = 20
        _native_type = "wc_Sha *"
        _native_size = _ffi.sizeof("wc_Sha")
        _delete = staticmethod(_lib.wc_ShaFree)
        _copy = staticmethod(_lib.wc_ShaCopy)

        def __del__(self):
            if hasattr(self, '_native_object') and not getattr(self, '_shallow_copy', False):
                self._delete(self._native_object)

        def _init(self):
            return _lib.wc_InitSha(self._native_object)

        def _update(self, data):
            return _lib.wc_ShaUpdate(self._native_object, data, len(data))

        def _final(self, obj, ret):
            return _lib.wc_ShaFinal(obj, ret)


if _lib.SHA256_ENABLED:
    class Sha256(_Hash):
        """
        **SHA-256** is a cryptographic hash function from the
        **SHA-2 family** and is standardized by **NIST**.

        It produces a [ **256-bit | 32 bytes** ] message digest.
        """
        digest_size = 32
        _native_type = "wc_Sha256 *"
        _native_size = _ffi.sizeof("wc_Sha256")
        _delete = staticmethod(_lib.wc_Sha256Free)
        _copy = staticmethod(_lib.wc_Sha256Copy)

        def __del__(self):
            if hasattr(self, '_native_object') and not getattr(self, '_shallow_copy', False):
                self._delete(self._native_object)

        def _init(self):
            return _lib.wc_InitSha256(self._native_object)

        def _update(self, data):
            return _lib.wc_Sha256Update(self._native_object, data, len(data))

        def _final(self, obj, ret):
            return _lib.wc_Sha256Final(obj, ret)


if _lib.SHA384_ENABLED:
    class Sha384(_Hash):
        """
        **SHA-384** is a cryptographic hash function from the
        **SHA-2 family** and is standardized by **NIST**.

        It produces a [ **384-bit | 48 bytes** ] message digest.
        """
        digest_size = 48
        _native_type = "wc_Sha384 *"
        _native_size = _ffi.sizeof("wc_Sha384")
        _delete = staticmethod(_lib.wc_Sha384Free)
        _copy = staticmethod(_lib.wc_Sha384Copy)

        def __del__(self):
            if hasattr(self, '_native_object') and not getattr(self, '_shallow_copy', False):
                self._delete(self._native_object)

        def _init(self):
            return _lib.wc_InitSha384(self._native_object)

        def _update(self, data):
            return _lib.wc_Sha384Update(self._native_object, data, len(data))

        def _final(self, obj, ret):
            return _lib.wc_Sha384Final(obj, ret)


if _lib.SHA512_ENABLED:
    class Sha512(_Hash):
        """
        **SHA-512** is a cryptographic hash function from the
        **SHA-2 family** and is standardized by **NIST**.

        It produces a [ **512-bit | 64 bytes** ] message digest.
        """
        digest_size = 64
        _native_type = "wc_Sha512 *"
        _native_size = _ffi.sizeof("wc_Sha512")
        _delete = staticmethod(_lib.wc_Sha512Free)
        _copy = staticmethod(_lib.wc_Sha512Copy)

        def __del__(self):
            if hasattr(self, '_native_object') and not getattr(self, '_shallow_copy', False):
                self._delete(self._native_object)

        def _init(self):
            return _lib.wc_InitSha512(self._native_object)

        def _update(self, data):
            return _lib.wc_Sha512Update(self._native_object, data, len(data))

        def _final(self, obj, ret):
            return _lib.wc_Sha512Final(obj, ret)

if _lib.SHA3_ENABLED:
    class Sha3(_Hash):
        """
        **SHA3 ** is a cryptographic hash function family
        standardized by **NIST**.

        It produces from [ **224-bit | 28 bytes** ] up to [ **512-bit | 64 bytes]  message digests.

        Using SHA3-384 by default, unless a different digest size is passed through __init__.
        """
        _native_type = "wc_Sha3 *"
        _native_size = _ffi.sizeof("wc_Sha3")
        SHA3_224_DIGEST_SIZE = 28
        SHA3_256_DIGEST_SIZE = 32
        SHA3_384_DIGEST_SIZE = 48
        SHA3_512_DIGEST_SIZE = 64

        _SHA3_FREE = {
            28: _lib.wc_Sha3_224_Free,
            32: _lib.wc_Sha3_256_Free,
            48: _lib.wc_Sha3_384_Free,
            64: _lib.wc_Sha3_512_Free,
        }

        _SHA3_COPY = {
            28: _lib.wc_Sha3_224_Copy,
            32: _lib.wc_Sha3_256_Copy,
            48: _lib.wc_Sha3_384_Copy,
            64: _lib.wc_Sha3_512_Copy,
        }

        def __del__(self):
            # Unlike the SHA-1/2 classes, Sha3's _delete is set per-instance
            # from a size->function dict and is None for invalid sizes, so
            # we need the extra truthiness check.
            if (hasattr(self, '_native_object')
                    and not getattr(self, '_shallow_copy', False)
                    and getattr(self, '_delete', None)):
                self._delete(self._native_object)

        def __init__(self, string=None, size=SHA3_384_DIGEST_SIZE):  # pylint: disable=W0231
            self._native_object = _ffi.new(self._native_type)
            self._shallow_copy = False
            self.digest_size = size
            self._delete = self._SHA3_FREE.get(size)
            self._copy = self._SHA3_COPY.get(size)
            ret = self._init()
            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("Sha3 init error", ret)
            if string:
                self.update(string)

        @classmethod
        def new(cls, string=None, size=SHA3_384_DIGEST_SIZE):
            return cls(string, size)

        def copy(self):
            # Bypass __init__ to avoid calling _init() on a state that _copy
            # immediately overwrites (which would leak internal resources in
            # async/HW-accelerated builds). Mark as shallow up front so
            # __del__ skips the free if we bail out before the copy completes.
            c = type(self).__new__(type(self))
            c._shallow_copy = True
            c._native_object = _ffi.new(self._native_type)
            c.digest_size = self.digest_size
            c._delete = self._delete
            c._copy = self._copy
            if self._copy:
                ret = self._copy(self._native_object, c._native_object)
                if ret < 0:  # pragma: no cover
                    # Free any partial allocation before raising.
                    if self._delete:
                        self._delete(c._native_object)
                    raise WolfCryptApiError("Hash copy error", ret)
                c._shallow_copy = False
            else:
                _ffi.memmove(c._native_object, self._native_object, self._native_size)
                # Keep _shallow_copy = True: memmove shares state with self.
            return c

        def _init(self):
            if (self.digest_size != Sha3.SHA3_224_DIGEST_SIZE and
                    self.digest_size != Sha3.SHA3_256_DIGEST_SIZE and
                    self.digest_size != Sha3.SHA3_384_DIGEST_SIZE and
                    self.digest_size != Sha3.SHA3_512_DIGEST_SIZE):
                return -1
            if self.digest_size == Sha3.SHA3_224_DIGEST_SIZE:
                return _lib.wc_InitSha3_224(self._native_object, _ffi.NULL, 0)
            if self.digest_size == Sha3.SHA3_256_DIGEST_SIZE:
                return _lib.wc_InitSha3_256(self._native_object, _ffi.NULL, 0)
            if self.digest_size == Sha3.SHA3_384_DIGEST_SIZE:
                return _lib.wc_InitSha3_384(self._native_object, _ffi.NULL, 0)
            if self.digest_size == Sha3.SHA3_512_DIGEST_SIZE:
                return _lib.wc_InitSha3_512(self._native_object, _ffi.NULL, 0)
        def _update(self, data):
            if self.digest_size == Sha3.SHA3_224_DIGEST_SIZE:
                return _lib.wc_Sha3_224_Update(self._native_object, data, len(data))
            if self.digest_size == Sha3.SHA3_256_DIGEST_SIZE:
                return _lib.wc_Sha3_256_Update(self._native_object, data, len(data))
            if self.digest_size == Sha3.SHA3_384_DIGEST_SIZE:
                return _lib.wc_Sha3_384_Update(self._native_object, data, len(data))
            if self.digest_size == Sha3.SHA3_512_DIGEST_SIZE:
                return _lib.wc_Sha3_512_Update(self._native_object, data, len(data))
        def _final(self, obj, ret):
            if self.digest_size == Sha3.SHA3_224_DIGEST_SIZE:
                return _lib.wc_Sha3_224_Final(obj, ret)
            if self.digest_size == Sha3.SHA3_256_DIGEST_SIZE:
                return _lib.wc_Sha3_256_Final(obj, ret)
            if self.digest_size == Sha3.SHA3_384_DIGEST_SIZE:
                return _lib.wc_Sha3_384_Final(obj, ret)
            if self.digest_size == Sha3.SHA3_512_DIGEST_SIZE:
                return _lib.wc_Sha3_512_Final(obj, ret)

# Hmac types

if _lib.FIPS_ENABLED and _lib.FIPS_VERSION <= 2:
    _TYPE_SHA = 1
    _TYPE_SHA256 = 2
    _TYPE_SHA384 = 5
    _TYPE_SHA512 = 4
else:
    _TYPE_SHA = 4
    _TYPE_SHA256 = 6
    _TYPE_SHA384 = 7
    _TYPE_SHA512 = 8

_HMAC_TYPES = [_TYPE_SHA, _TYPE_SHA256, _TYPE_SHA384, _TYPE_SHA512]


if _lib.HMAC_ENABLED:
    class _Hmac(_Hash):
        """
        A **PEP 247: Cryptographic Hash Functions** compliant
        **Keyed Hash Function Interface**.

        Note: wolfSSL does not provide a `wc_HmacCopy` equivalent, so
        `copy()` falls back to a byte-level memmove. In default builds the
        Hmac struct is self-contained and this is safe. In async or
        hardware-accelerated builds where the struct contains internal
        pointers, the copy shares those pointers with the original; the
        copy must not outlive the original or be used after the original
        is freed.
        """
        digest_size = None
        _native_type = "Hmac *"
        _native_size = _ffi.sizeof("Hmac")
        _delete = staticmethod(_lib.wc_HmacFree)

        def __del__(self):
            if hasattr(self, '_native_object') and not getattr(self, '_shallow_copy', False):
                self._delete(self._native_object)

        def __init__(self, key, string=None):  # pylint: disable=W0231
            key = t2b(key)

            self._native_object = _ffi.new(self._native_type)
            self._shallow_copy = False
            ret = self._init(self._type, key)
            if ret < 0:  # pragma: no cover
                raise WolfCryptApiError("Hmac init error", ret)

            if string:
                self.update(string)

        @classmethod
        def new(cls, key, string=None):  # pylint: disable=W0221
            """
            Creates a new hashing object and returns it. **key** is
            a required parameter containing a string giving the key
            to use. The optional **string** parameter, if supplied,
            will be immediately hashed into the object's starting
            state, as if obj.update(string) was called.
            """
            return cls(key, string)

        def _init(self, hmac, key):
            ret = _lib.wc_HmacInit(self._native_object, _ffi.NULL, -2)
            if ret < 0:
                raise WolfCryptApiError("wc_HmacInit error", ret)
            # If the key isn't set, don't call wc_HmacSetKey. This can happen,
            # for example, when the HMAC object is being copied. See the copy
            # function of _Hash.
            ret = 0
            if len(key) > 0:
                ret = _lib.wc_HmacSetKey(self._native_object, hmac, key, len(key))
                if ret < 0:
                    raise WolfCryptApiError("wc_HmacSetKey error", ret)
            return ret

        def _update(self, data):
            return _lib.wc_HmacUpdate(self._native_object, data, len(data))

        def _final(self, obj, ret):
            return _lib.wc_HmacFinal(obj, ret)


    if _lib.SHA_ENABLED:
        class HmacSha(_Hmac):
            """
            A HMAC function using **SHA-1** as it's cryptographic
            hash function.

            It produces a [ **512-bit | 64 bytes** ] message digest.
            """
            _type = _TYPE_SHA
            digest_size = Sha.digest_size


    if _lib.SHA256_ENABLED:
        class HmacSha256(_Hmac):
            """
            A HMAC function using **SHA-256** as it's cryptographic
            hash function.

            It produces a [ **512-bit | 64 bytes** ] message digest.
            """
            _type = _TYPE_SHA256
            digest_size = Sha256.digest_size


    if _lib.SHA384_ENABLED:
        class HmacSha384(_Hmac):
            """
            A HMAC function using **SHA-384** as it's cryptographic
            hash function.

            It produces a [ **512-bit | 64 bytes** ] message digest.
            """
            _type = _TYPE_SHA384
            digest_size = Sha384.digest_size


    if _lib.SHA512_ENABLED:
        class HmacSha512(_Hmac):
            """
            A HMAC function using **SHA-512** as it's cryptographic
            hash function.

            It produces a [ **512-bit | 64 bytes** ] message digest.
            """
            _type = _TYPE_SHA512
            digest_size = Sha512.digest_size

def hash_type_to_cls(hash_type):
    if _lib.SHA_ENABLED and hash_type == _lib.WC_HASH_TYPE_SHA:
        hash_cls = Sha
    elif _lib.SHA256_ENABLED and hash_type == _lib.WC_HASH_TYPE_SHA256:
        hash_cls = Sha256
    elif _lib.SHA384_ENABLED and hash_type == _lib.WC_HASH_TYPE_SHA384:
        hash_cls = Sha384
    elif _lib.SHA512_ENABLED and hash_type == _lib.WC_HASH_TYPE_SHA512:
        hash_cls = Sha512
    else:
        hash_cls = None

    return hash_cls
