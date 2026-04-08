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

from typing import Final
from typing_extensions import Self

from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib

from wolfcrypt.exceptions import WolfCryptError

ALGO_TYPE_NAME: Final = {
    _lib.WC_ALGO_TYPE_HASH: "hash",
    _lib.WC_ALGO_TYPE_CIPHER: "cipher",
    _lib.WC_ALGO_TYPE_RNG: "rng",
    _lib.WC_ALGO_TYPE_SEED: "seed",
}

HASH_TYPE_NAME: Final = {
    _lib.WC_HASH_TYPE_SHA: "SHA1",
    _lib.WC_HASH_TYPE_SHA256: "SHA256",
    _lib.WC_HASH_TYPE_SHA384: "SHA384",
    _lib.WC_HASH_TYPE_SHA512: "SHA512",
    _lib.WC_HASH_TYPE_SHA3_256: "SHA3_256",
    _lib.WC_HASH_TYPE_SHA3_384: "SHA3_384",
    _lib.WC_HASH_TYPE_SHA3_512: "SHA3_512",
}

DIGEST_SIZE: Final = {
    _lib.WC_HASH_TYPE_SHA: 20,
    _lib.WC_HASH_TYPE_SHA256: 32,
    _lib.WC_HASH_TYPE_SHA384: 48,
    _lib.WC_HASH_TYPE_SHA512: 64,
    _lib.WC_HASH_TYPE_SHA3_256: 32,
    _lib.WC_HASH_TYPE_SHA3_384: 48,
    _lib.WC_HASH_TYPE_SHA3_512: 64,
}


if _lib.CRYPTO_CB_ENABLED:
    class CryptoCallback:
        def __init__(self, device_id: int):
            self.device_id = device_id
            self.ctx = _ffi.new_handle(self)
            ret = _lib.wc_CryptoCb_RegisterDevice(device_id, _lib.py_wc_crypto_callback, self.ctx)
            if ret < 0:  # pragma: no cover
                raise WolfCryptError(f"CryptoCb device registration error ({ret})")

        def __enter__(self) -> Self:
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            self._unregister()

        def __del__(self) -> None:
            self._unregister()

        def callback(self, device_id: int, info: _ffi.CData) -> int:
            print(f"{device_id=} algo = {ALGO_TYPE_NAME[info.algo_type]}")
            # _lib.wc_CryptoCb_InfoString(info)
            try:
                if info.algo_type == _lib.WC_ALGO_TYPE_HASH:
                    print(f"hash = {HASH_TYPE_NAME[info.hash.type]}")
                    print(f"{info.hash.data=} {info.hash.data_size=} {info.hash.digest=} {info.hash.u.sha256=}")
                    if info.hash.digest == _ffi.NULL:
                        self.hash_update_callback(device_id, info.hash.type, bytes(_ffi.buffer(info.hash.data, info.hash.data_size)))
                    else:
                        digest = self.hash_finalize_callback(device_id, info.hash.type)
                        _ffi.buffer(info.hash.digest, DIGEST_SIZE[info.hash.type])[:] = digest
                    return 0
                if info.algo_type == _lib.WC_ALGO_TYPE_CIPHER:
                    self.cipher_callback(device_id)
                    return 0
                if info.algo_type == _lib.WC_ALGO_TYPE_RNG:
                    out = self.rng_callback(device_id, info.rng.rng, info.rng.sz)
                    _ffi.buffer(info.rng.out, info.rng.sz)[:] = out
                    return 0
                return _lib.CRYPTOCB_UNAVAILABLE
            except NotImplementedError:
                return _lib.CRYPTOCB_UNAVAILABLE

        def rng_callback(self, device_id: int, rng, size: int) -> bytes:
            raise NotImplementedError

        def hash_update_callback(self, device_id: int, hash_type: int, data: bytes) -> None:
            print("hash_update_callback")
            raise NotImplementedError

        def hash_finalize_callback(self, device_id: int, hash_type: int) -> bytes:
            print("hash_finalize_callback")
            raise NotImplementedError

        def cipher_callback(self, device_id: int) -> None:
            raise NotImplementedError

        def _unregister(self) -> None:
            _lib.wc_CryptoCb_UnRegisterDevice(self.device_id)

        @classmethod
        def default_device_id(cls) -> int:
            return _lib.wc_CryptoCb_DefaultDevID()
