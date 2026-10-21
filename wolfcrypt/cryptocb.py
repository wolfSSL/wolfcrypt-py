# cryptocb.py
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

# pylint: disable=no-member,no-name-in-module

from __future__ import annotations

import copy
import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Any, ClassVar, Final

from typing_extensions import Self

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib
from wolfcrypt.exceptions import WolfCryptError

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from _cffi_backend import FFI

log = logging.getLogger(__name__)

if _lib.CRYPTO_CB_ENABLED:

    ALGO_TYPE_NAME: Final = defaultdict(
        lambda: "unknown",
        {
            _lib.WC_ALGO_TYPE_NONE: "none",
            _lib.WC_ALGO_TYPE_HASH: "hash",
            _lib.WC_ALGO_TYPE_CIPHER: "cipher",
            _lib.WC_ALGO_TYPE_PK: "pk",
            _lib.WC_ALGO_TYPE_RNG: "rng",
            _lib.WC_ALGO_TYPE_SEED: "seed",
            _lib.WC_ALGO_TYPE_HMAC: "hmac",
            _lib.WC_ALGO_TYPE_CMAC: "cmac",
            _lib.WC_ALGO_TYPE_CERT: "cert",
            _lib.WC_ALGO_TYPE_KDF: "kdf",
            _lib.WC_ALGO_TYPE_COPY: "copy",
            _lib.WC_ALGO_TYPE_FREE: "free",
            _lib.WC_ALGO_TYPE_MAX: "max",
        },
    )

    HASH_TYPE_NAME: Final = defaultdict(
        lambda: "unknown",
        {
            _lib.WC_HASH_TYPE_SHA: "SHA1",
            _lib.WC_HASH_TYPE_SHA256: "SHA256",
            _lib.WC_HASH_TYPE_SHA384: "SHA384",
            _lib.WC_HASH_TYPE_SHA512: "SHA512",
            _lib.WC_HASH_TYPE_SHA3_256: "SHA3_256",
            _lib.WC_HASH_TYPE_SHA3_384: "SHA3_384",
            _lib.WC_HASH_TYPE_SHA3_512: "SHA3_512",
        },
    )

    DIGEST_SIZE: Final = {
        _lib.WC_HASH_TYPE_SHA: 20,
        _lib.WC_HASH_TYPE_SHA256: 32,
        _lib.WC_HASH_TYPE_SHA384: 48,
        _lib.WC_HASH_TYPE_SHA512: 64,
        _lib.WC_HASH_TYPE_SHA3_256: 32,
        _lib.WC_HASH_TYPE_SHA3_384: 48,
        _lib.WC_HASH_TYPE_SHA3_512: 64,
    }

    # Native type and wolfCrypt copy function for each hash type
    NATIVE_HASH_COPY: Final[dict[int, tuple[str, Callable[[FFI.CData, FFI.CData], int]]]] = {}
    if _lib.SHA_ENABLED:
        NATIVE_HASH_COPY[_lib.WC_HASH_TYPE_SHA] = ("wc_Sha *", _lib.wc_ShaCopy)
    if _lib.SHA256_ENABLED:
        NATIVE_HASH_COPY[_lib.WC_HASH_TYPE_SHA256] = ("wc_Sha256 *", _lib.wc_Sha256Copy)
    if _lib.SHA384_ENABLED:
        NATIVE_HASH_COPY[_lib.WC_HASH_TYPE_SHA384] = ("wc_Sha384 *", _lib.wc_Sha384Copy)
    if _lib.SHA512_ENABLED:
        NATIVE_HASH_COPY[_lib.WC_HASH_TYPE_SHA512] = ("wc_Sha512 *", _lib.wc_Sha512Copy)
    if _lib.SHA3_ENABLED:
        NATIVE_HASH_COPY[_lib.WC_HASH_TYPE_SHA3_256] = ("wc_Sha3 *", _lib.wc_Sha3_256_Copy)
        NATIVE_HASH_COPY[_lib.WC_HASH_TYPE_SHA3_384] = ("wc_Sha3 *", _lib.wc_Sha3_384_Copy)
        NATIVE_HASH_COPY[_lib.WC_HASH_TYPE_SHA3_512] = ("wc_Sha3 *", _lib.wc_Sha3_512_Copy)


    class CryptoCallback:
        """
        Registers a wolfCrypt crypto callback device for **device_id**.
        Subclasses override rng_callback, or both hash_update_callback
        and hash_finalize_callback. Operations that are not overridden
        fall back to the software implementation.

        Each hash object has its own context dict, passed to both hash
        hooks for keeping per-hash state. It is deep-copied when the hash
        object is copied, so its values must support copy.deepcopy, and it
        is discarded when the hash is finalized or freed.
        Hash callbacks need wolfSSL built with copy and free callback support
        (--enable-cryptocbutils=copy,free); without it hashing falls back to
        the software implementation.
        """

        # Keeps each registered instance (and its ctx handle) alive until it is
        # unregistered, and records which instance owns a device id.
        _registered: ClassVar[dict[int, CryptoCallback]] = {}

        def __init__(self, device_id: int) -> None:
            self.device_id = device_id
            self._hash_contexts: dict[int, dict[str, Any]] = {}
            # (src, dst) addresses of native hash copies in progress
            self._hash_copies: set[tuple[int, int]] = set()
            self.ctx = _ffi.new_handle(self)
            ret = _lib.wc_CryptoCb_RegisterDevice(device_id, _lib.py_wc_crypto_callback, self.ctx)
            if ret < 0:  # pragma: no cover
                raise WolfCryptError(f"CryptoCb device registration error ({ret})")
            CryptoCallback._registered[device_id] = self

        def __enter__(self) -> Self:
            return self

        def __exit__(
            self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
        ) -> None:
            self._unregister()

        def __del__(self) -> None:
            try:
                self._unregister()
            except AttributeError:
                # Can occur during interpreter shutdown
                pass

        def callback(self, device_id: int, info: _lib.wc_CryptoInfo) -> int:
            log.debug("device_id=%d algo_type = %s", device_id, ALGO_TYPE_NAME[info.algo_type])
            try:
                if info.algo_type == _lib.WC_ALGO_TYPE_HASH:
                    if info.hash.type not in DIGEST_SIZE or not self._handles_hash():
                        return _lib.CRYPTOCB_UNAVAILABLE
                    log.debug("hash_type = %s", HASH_TYPE_NAME[info.hash.type])
                    key = _address(info.hash.u.ctx)
                    context = self._hash_contexts.setdefault(key, {})
                    if info.hash.digest == _ffi.NULL:
                        self.hash_update_callback(
                            device_id,
                            info.hash.type,
                            context,
                            bytes(_ffi.buffer(info.hash.data, info.hash.data_size)),
                        )
                    else:
                        digest = self.hash_finalize_callback(device_id, info.hash.type, context)
                        # wolfCrypt resets a hash object after Final
                        del self._hash_contexts[key]
                        if len(digest) != DIGEST_SIZE[info.hash.type]:
                            raise ValueError(
                                f"Generated digest is expected to be {DIGEST_SIZE[info.hash.type]} bytes long, "
                                f"but is {len(digest)} bytes long"
                            )
                        _ffi.buffer(info.hash.digest, DIGEST_SIZE[info.hash.type])[:] = digest
                    return 0
                if info.algo_type == _lib.WC_ALGO_TYPE_RNG:
                    out = self.rng_callback(device_id, info.rng.rng, info.rng.sz)
                    if len(out) != info.rng.sz:
                        raise ValueError(
                            f"Generated random is expected to be {info.rng.sz} bytes long, but is {len(out)} bytes long"
                        )
                    _ffi.buffer(info.rng.out, info.rng.sz)[:] = out
                    return 0
                if info.algo_type == _lib.WC_ALGO_TYPE_COPY and info.copy.algo == _lib.WC_ALGO_TYPE_HASH:
                    return self._hash_copy(info.copy.type, info.copy.src, info.copy.dst)
                if info.algo_type == _lib.WC_ALGO_TYPE_FREE and info.free.algo == _lib.WC_ALGO_TYPE_HASH:
                    self._hash_contexts.pop(_address(info.free.obj), None)
                    # Let wolfCrypt free the native object
                    return _lib.CRYPTOCB_UNAVAILABLE
                return _lib.CRYPTOCB_UNAVAILABLE
            except NotImplementedError:
                return _lib.CRYPTOCB_UNAVAILABLE

        def rng_callback(self, device_id: int, rng: _lib.RNG, size: int) -> bytes:
            raise NotImplementedError

        def hash_update_callback(self, device_id: int, hash_type: int, context: dict[str, Any], data: bytes) -> None:
            raise NotImplementedError

        def hash_finalize_callback(self, device_id: int, hash_type: int, context: dict[str, Any]) -> bytes:
            raise NotImplementedError

        def _hash_copy(self, hash_type: int, src: FFI.CData, dst: FFI.CData) -> int:
            src_key = _address(src)
            dst_key = _address(dst)
            native = NATIVE_HASH_COPY.get(hash_type)
            if (
                native is None
                or src_key not in self._hash_contexts
                or (src_key, dst_key) in self._hash_copies
            ):
                return _lib.CRYPTOCB_UNAVAILABLE
            # Re-enter wolfCrypt's copy so it deep copies the native object
            # (e.g. the SMALL_STACK_CACHE W buffer). The nested copy callback
            # returns CRYPTOCB_UNAVAILABLE above, and the free of dst it does
            # first drops any old context for dst.
            ptr_type, copy_fn = native
            self._hash_copies.add((src_key, dst_key))
            try:
                ret = copy_fn(_ffi.cast(ptr_type, src), _ffi.cast(ptr_type, dst))
            finally:
                self._hash_copies.discard((src_key, dst_key))
            if ret == 0:
                self._hash_contexts[dst_key] = copy.deepcopy(self._hash_contexts[src_key])
            return ret

        def _handles_hash(self) -> bool:
            # Update and finalize must both go to the callback, otherwise wolfCrypt
            # would hash the data in software and finalize would ignore it.
            # Without copy and free callbacks a hash context could not follow
            # its native object.
            if not (_lib.CRYPTO_CB_COPY_ENABLED and _lib.CRYPTO_CB_FREE_ENABLED):
                return False
            cls = type(self)
            return (
                cls.hash_update_callback is not CryptoCallback.hash_update_callback
                and cls.hash_finalize_callback is not CryptoCallback.hash_finalize_callback
            )

        def _unregister(self) -> None:
            if CryptoCallback._registered.get(self.device_id) is self:
                del CryptoCallback._registered[self.device_id]
                _lib.wc_CryptoCb_UnRegisterDevice(self.device_id)

        @classmethod
        def default_device_id(cls) -> int:
            return _lib.wc_CryptoCb_DefaultDevID()


    def _address(ptr: FFI.CData) -> int:
        return int(_ffi.cast("uintptr_t", ptr))
