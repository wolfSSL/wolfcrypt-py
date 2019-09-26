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

import os
import sys
from distutils.util import get_platform
from cffi import FFI
from wolfcrypt import __wolfssl_version__ as version
from wolfcrypt._build_wolfssl import wolfssl_inc_path, wolfssl_lib_path

# detect features if user has built against local wolfSSL library
# if they are not, we are controlling build options in _build_wolfssl.py
local_wolfssl = os.environ.get("USE_LOCAL_WOLFSSL")
if local_wolfssl is not None:
    # Try to do native wolfSSL/wolfCrypt feature detection.
    # Open <wolfssl/options.h> header to parse for #define's
    # This will throw a FileNotFoundError if not able to find options.h
    optionsHeaderPath = wolfssl_inc_path() + "/wolfssl/options.h"
    optionsHeader = open(optionsHeaderPath, 'r')
    optionsHeaderStr = optionsHeader.read()
    optionsHeader.close()
    featureDetection = 1
    sys.stderr.write("\nDEBUG: Found <wolfssl/options.h>, attempting native "
                     "feature detection\n")

else:
    optionsHeaderStr = ""
    featureDetection = 0
    sys.stderr.write("\nDEBUG: Skipping native feature detection, build not "
                     "using USE_LOCAL_WOLFSSL\n")

# default values
MPAPI_ENABLED = 0
SHA_ENABLED = 1
SHA256_ENABLED = 1
SHA384_ENABLED = 1
SHA512_ENABLED = 1
DES3_ENABLED = 1
AES_ENABLED = 1
HMAC_ENABLED = 1
RSA_ENABLED = 1
ECC_ENABLED = 1
ED25519_ENABLED = 1
KEYGEN_ENABLED = 1

# detect native features based on options.h defines
if featureDetection == 1:
    if '#define WOLFSSL_PUBLIC_MP' in optionsHeaderStr:
        MPAPI_ENABLED = 1
    else:
        MPAPI_ENABLED = 0

    if '#define NO_SHA' in optionsHeaderStr:
        SHA_ENABLED = 0
    else:
        SHA_ENABLED = 1

    if '#define NO_SHA256' in optionsHeaderStr:
        SHA256_ENABLED = 0
    else:
        SHA256_ENABLED = 1

    if '#define WOLFSSL_SHA384' in optionsHeaderStr:
        SHA384_ENABLED = 1
    else:
        SHA384_ENABLED = 0

    if '#define WOLFSSL_SHA512' in optionsHeaderStr:
        SHA512_ENABLED = 1
    else:
        SHA512_ENABLED = 0

    if '#define NO_DES3' in optionsHeaderStr:
        DES3_ENABLED = 0
    else:
        DES3_ENABLED = 1

    if '#define NO_AES' in optionsHeaderStr:
        AES_ENABLED = 0
    else:
        AES_ENABLED = 1

    if '#define NO_HMAC' in optionsHeaderStr:
        HMAC_ENABLED = 0
    else:
        HMAC_ENABLED = 1

    if '#define NO_RSA' in optionsHeaderStr:
        RSA_ENABLED = 0
    else:
        RSA_ENABLED = 1

    if '#define HAVE_ECC' in optionsHeaderStr:
        ECC_ENABLED = 1
    else:
        ECC_ENABLED = 0

    if '#define HAVE_ED25519' in optionsHeaderStr:
        ED25519_ENABLED = 1
    else:
        ED25519_ENABLED = 0

    if '#define WOLFSSL_KEY_GEN' in optionsHeaderStr:
        KEYGEN_ENABLED = 1
    else:
        KEYGEN_ENABLED = 0


# build cffi module, wrapping native wolfSSL
ffibuilder = FFI()

ffibuilder.set_source(
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
    #include <wolfssl/wolfcrypt/ed25519.h>
    #include <wolfssl/wolfcrypt/curve25519.h>

    int MPAPI_ENABLED = """ + str(MPAPI_ENABLED) + """;
    int SHA_ENABLED = """ + str(SHA_ENABLED) + """;
    int SHA256_ENABLED = """ + str(SHA256_ENABLED) + """;
    int SHA384_ENABLED = """ + str(SHA384_ENABLED) + """;
    int SHA512_ENABLED = """ + str(SHA512_ENABLED) + """;
    int DES3_ENABLED = """ + str(DES3_ENABLED) + """;
    int AES_ENABLED = """ + str(AES_ENABLED) + """;
    int HMAC_ENABLED = """ + str(HMAC_ENABLED) + """;
    int RSA_ENABLED = """ + str(RSA_ENABLED) + """;
    int ECC_ENABLED = """ + str(ECC_ENABLED) + """;
    int ED25519_ENABLED = """ + str(ED25519_ENABLED) + """;
    int KEYGEN_ENABLED = """ + str(KEYGEN_ENABLED) + """;

    """,
    include_dirs=[wolfssl_inc_path()],
    library_dirs=[wolfssl_lib_path()],
    libraries=["wolfssl"],
)

_cdef = """
    int MPAPI_ENABLED;
    int SHA_ENABLED;
    int SHA256_ENABLED;
    int SHA384_ENABLED;
    int SHA512_ENABLED;
    int DES3_ENABLED;
    int AES_ENABLED;
    int HMAC_ENABLED;
    int RSA_ENABLED;
    int ECC_ENABLED;
    int ED25519_ENABLED;
    int KEYGEN_ENABLED;

    typedef unsigned char byte;
    typedef unsigned int word32;

    typedef struct { ...; } WC_RNG;
    int wc_InitRng(WC_RNG*);
    int wc_RNG_GenerateBlock(WC_RNG*, byte*, word32);
    int wc_RNG_GenerateByte(WC_RNG*, byte*);
    int wc_FreeRng(WC_RNG*);


"""

if (MPAPI_ENABLED == 1):
    _cdef += """
    typedef struct { ...; } mp_int;

    int mp_init (mp_int * a);
    int mp_to_unsigned_bin (mp_int * a, unsigned char *b);
    int mp_read_unsigned_bin (mp_int * a, const unsigned char *b, int c);
    """

if (SHA_ENABLED == 1):
    _cdef += """
    typedef struct { ...; } wc_Sha;
    int wc_InitSha(wc_Sha*);
    int wc_ShaUpdate(wc_Sha*, const byte*, word32);
    int wc_ShaFinal(wc_Sha*, byte*);
    """

if (SHA256_ENABLED == 1):
    _cdef += """
    typedef struct { ...; } wc_Sha256;
    int wc_InitSha256(wc_Sha256*);
    int wc_Sha256Update(wc_Sha256*, const byte*, word32);
    int wc_Sha256Final(wc_Sha256*, byte*);
    """

if (SHA384_ENABLED == 1):
    _cdef += """
    typedef struct { ...; } wc_Sha384;
    int wc_InitSha384(wc_Sha384*);
    int wc_Sha384Update(wc_Sha384*, const byte*, word32);
    int wc_Sha384Final(wc_Sha384*, byte*);
    """

if (SHA512_ENABLED == 1):
    _cdef += """
    typedef struct { ...; } wc_Sha512;

    int wc_InitSha512(wc_Sha512*);
    int wc_Sha512Update(wc_Sha512*, const byte*, word32);
    int wc_Sha512Final(wc_Sha512*, byte*);
    """

if (DES3_ENABLED == 1):
    _cdef += """
        typedef struct { ...; } Des3;
        int wc_Des3_SetKey(Des3*, const byte*, const byte*, int);
        int wc_Des3_CbcEncrypt(Des3*, byte*, const byte*, word32);
        int wc_Des3_CbcDecrypt(Des3*, byte*, const byte*, word32);
    """

if (AES_ENABLED == 1):
    _cdef += """
    typedef struct { ...; } Aes;

    int wc_AesSetKey(Aes*, const byte*, word32, const byte*, int);
    int wc_AesCbcEncrypt(Aes*, byte*, const byte*, word32);
    int wc_AesCbcDecrypt(Aes*, byte*, const byte*, word32);
    """

if (HMAC_ENABLED == 1):
    _cdef += """
    typedef struct { ...; } Hmac;
    int wc_HmacInit(Hmac* hmac, void* heap, int devId);
    int wc_HmacSetKey(Hmac*, int, const byte*, word32);
    int wc_HmacUpdate(Hmac*, const byte*, word32);
    int wc_HmacFinal(Hmac*, byte*);
    """

if (RSA_ENABLED == 1):
    _cdef += """
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
    """

    if (KEYGEN_ENABLED):
        _cdef += """
        int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng);
        int wc_RsaKeyToDer(RsaKey* key, byte* output, word32 inLen);
        int wc_RsaKeyToPublicDer(RsaKey* key, byte* output, word32 inLen);

        """

if (ECC_ENABLED == 1):
    _cdef += """
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
    int wc_ecc_export_private_raw(ecc_key* key, byte* qx, word32* qxLen,
                              byte* qy, word32* qyLen, byte* d, word32* dLen);
    int wc_ecc_import_unsigned(ecc_key* key, byte* qx, byte* qy,
                   byte* d, int curve_id);
    int wc_ecc_export_public_raw(ecc_key* key, byte* qx, word32* qxLen,
                             byte* qy, word32* qyLen);


    int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
                             byte* out, word32* outlen);

    int wc_ecc_sign_hash(const byte* in, word32 inlen,
                         byte* out, word32 *outlen,
                         WC_RNG* rng, ecc_key* key);
    int wc_ecc_verify_hash(const byte* sig, word32 siglen,
                           const byte* hash, word32 hashlen,
                           int* stat, ecc_key* key);
    """

if (ECC_ENABLED == 1 and MPAPI_ENABLED == 1):
    _cdef += """
    int wc_ecc_sign_hash_ex(const byte* in, word32 inlen, WC_RNG* rng,
                     ecc_key* key, mp_int *r, mp_int *s);

    int wc_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                    word32 hashlen, int* res, ecc_key* key);
    """

if (ED25519_ENABLED == 1):
    _cdef += """
    typedef struct {...; } ed25519_key;

    int wc_ed25519_init(ed25519_key* ed25519);
    void wc_ed25519_free(ed25519_key* ed25519);

    int wc_ed25519_make_key(WC_RNG* rng, int keysize, ed25519_key* key);
    int wc_ed25519_make_public(ed25519_key* key, unsigned char* pubKey,
                           word32 pubKeySz);
    int wc_ed25519_size(ed25519_key* key);
    int wc_ed25519_sig_size(ed25519_key* key);
    int wc_ed25519_sign_msg(const byte* in, word32 inlen, byte* out,
                        word32 *outlen, ed25519_key* key);
    int wc_ed25519_verify_msg(const byte* sig, word32 siglen, const byte* msg,
                          word32 msglen, int* stat, ed25519_key* key);
    int wc_Ed25519PrivateKeyDecode(const byte*, word32*, ed25519_key*, word32);
    int wc_Ed25519KeyToDer(ed25519_key*, byte* output, word32 inLen);

    int wc_Ed25519PublicKeyDecode(const byte*, word32*, ed25519_key*, word32);
    int wc_Ed25519PublicKeyToDer(ed25519_key*, byte* output,
                             word32 inLen, int with_AlgCurve);

    int wc_ed25519_import_public(const byte* in, word32 inLen, ed25519_key* key);
    int wc_ed25519_import_private_only(const byte* priv, word32 privSz, ed25519_key* key);
    int wc_ed25519_import_private_key(const byte* priv, word32 privSz, const byte* pub, word32 pubSz, ed25519_key* key);
    int wc_ed25519_export_public(ed25519_key*, byte* out, word32* outLen);
    int wc_ed25519_export_private_only(ed25519_key* key, byte* out, word32* outLen);
    int wc_ed25519_export_private(ed25519_key* key, byte* out, word32* outLen);
    int wc_ed25519_export_key(ed25519_key* key, byte* priv, word32 *privSz, byte* pub, word32 *pubSz);
    int wc_ed25519_check_key(ed25519_key* key);
    int wc_ed25519_pub_size(ed25519_key* key);
    int wc_ed25519_priv_size(ed25519_key* key);
    """

ffibuilder.cdef(_cdef)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
