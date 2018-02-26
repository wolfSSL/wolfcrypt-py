# build_ffi.py
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

from distutils.util import get_platform
from cffi import FFI
from wolfcrypt import __wolfssl_version__ as version
from wolfcrypt._build_wolfssl import local_path

ffi = FFI()

ffi.set_source(
    "wolfcrypt._ffi",
    """
    #include <wolfssl/options.h>

    #include <wolfssl/wolfcrypt/sha.h>
    #include <wolfssl/wolfcrypt/sha256.h>
    #include <wolfssl/wolfcrypt/sha512.h>

    #include <wolfssl/wolfcrypt/hmac.h>

    #include <wolfssl/wolfcrypt/aes.h>
    #include <wolfssl/wolfcrypt/des3.h>
    #include <wolfssl/wolfcrypt/asn.h>

    #include <wolfssl/wolfcrypt/random.h>

    #include <wolfssl/wolfcrypt/rsa.h>
    #include <wolfssl/wolfcrypt/ecc.h>
    """,
    include_dirs=[local_path("lib/wolfssl/src")],
    library_dirs=[local_path("lib/wolfssl/{}/{}/lib".format(
        get_platform(), version))],
    libraries=["wolfssl"],
)

ffi.cdef(
    """
    typedef unsigned char byte;
    typedef unsigned int word32;


    typedef struct { ...; } wc_Sha;

    int wc_InitSha(wc_Sha*);
    int wc_ShaUpdate(wc_Sha*, const byte*, word32);
    int wc_ShaFinal(wc_Sha*, byte*);


    typedef struct { ...; } wc_Sha256;

    int wc_InitSha256(wc_Sha256*);
    int wc_Sha256Update(wc_Sha256*, const byte*, word32);
    int wc_Sha256Final(wc_Sha256*, byte*);


    typedef struct { ...; } wc_Sha384;

    int wc_InitSha384(wc_Sha384*);
    int wc_Sha384Update(wc_Sha384*, const byte*, word32);
    int wc_Sha384Final(wc_Sha384*, byte*);


    typedef struct { ...; } wc_Sha512;

    int wc_InitSha512(wc_Sha512*);
    int wc_Sha512Update(wc_Sha512*, const byte*, word32);
    int wc_Sha512Final(wc_Sha512*, byte*);


    typedef struct { ...; } Hmac;

    int wc_HmacSetKey(Hmac*, int, const byte*, word32);
    int wc_HmacUpdate(Hmac*, const byte*, word32);
    int wc_HmacFinal(Hmac*, byte*);


    typedef struct { ...; } Aes;

    int wc_AesSetKey(Aes*, const byte*, word32, const byte*, int);
    int wc_AesCbcEncrypt(Aes*, byte*, const byte*, word32);
    int wc_AesCbcDecrypt(Aes*, byte*, const byte*, word32);


    typedef struct { ...; } Des3;

    int wc_Des3_SetKey(Des3*, const byte*, const byte*, int);
    int wc_Des3_CbcEncrypt(Des3*, byte*, const byte*, word32);
    int wc_Des3_CbcDecrypt(Des3*, byte*, const byte*, word32);


    typedef struct { ...; } WC_RNG;

    int wc_InitRng(WC_RNG*);
    int wc_RNG_GenerateBlock(WC_RNG*, byte*, word32);
    int wc_RNG_GenerateByte(WC_RNG*, byte*);
    int wc_FreeRng(WC_RNG*);


    typedef struct {...; } RsaKey;

    int wc_InitRsaKey(RsaKey* key, void*);
    int wc_RsaSetRNG(RsaKey* key, WC_RNG* rng);
    int wc_FreeRsaKey(RsaKey* key);

    int wc_RsaPrivateKeyDecode(const byte*, word32*, RsaKey*, word32);
    int wc_RsaPublicKeyDecode(const byte*, word32*, RsaKey*, word32);
    int wc_RsaEncryptSize(RsaKey*);

    int wc_RsaPrivateDecrypt(const byte*, word32, byte*, word32,
                            RsaKey* key);
    int wc_RsaPublicEncrypt(const byte*, word32, byte*, word32,
                            RsaKey*, WC_RNG*);

    int wc_RsaSSL_Sign(const byte*, word32, byte*, word32, RsaKey*, WC_RNG*);
    int wc_RsaSSL_Verify(const byte*, word32, byte*, word32, RsaKey*);

    typedef struct {...; } ecc_key;

    int wc_ecc_init(ecc_key* ecc);
    void wc_ecc_free(ecc_key* ecc);

    int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key);
    int wc_ecc_size(ecc_key* key);
    int wc_ecc_sig_size(ecc_key* key);

    int wc_EccPrivateKeyDecode(const byte*, word32*, ecc_key*, word32);
    int wc_EccKeyToDer(ecc_key*, byte* output, word32 inLen);

    int wc_EccPublicKeyDecode(const byte*, word32*, ecc_key*, word32);
    int wc_EccPublicKeyToDer(ecc_key*, byte* output,
                             word32 inLen, int with_AlgCurve);

    int wc_ecc_export_x963(ecc_key*, byte* out, word32* outLen);
    int wc_ecc_import_x963(const byte* in, word32 inLen, ecc_key* key);

    int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
                             byte* out, word32* outlen);

    int wc_ecc_sign_hash(const byte* in, word32 inlen,
                         byte* out, word32 *outlen,
                         WC_RNG* rng, ecc_key* key);
    int wc_ecc_verify_hash(const byte* sig, word32 siglen,
                           const byte* hash, word32 hashlen,
                           int* stat, ecc_key* key);

    """
)

if __name__ == "__main__":
    ffi.compile(verbose=1)
