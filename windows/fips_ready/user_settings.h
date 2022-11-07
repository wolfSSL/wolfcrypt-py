#ifndef _FIPS_READY_USER_SETTINGS_H_
#define _FIPS_READY_USER_SETTINGS_H_

/* Verify this is Windows */
#ifndef _WIN32
#error This user_settings.h header is only designed for Windows
#endif

#undef HAVE_FIPS
#define HAVE_FIPS
#undef HAVE_FIPS_VERSION
#define HAVE_FIPS_VERSION 5
#undef HAVE_FIPS_VERSION_MINOR
#define HAVE_FIPS_VERSION_MINOR 3

#define WOLFCRYPT_ONLY
#define HAVE_HASHDRBG
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AESGCM_STREAM
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define HAVE_HKDF
#define WOLFSSL_NO_SHAKE256
#define WC_RSA_PSS
#define WOLFSSL_PSS_LONG_SALT
#define HAVE_ECC
#define WOLFSSL_VALIDATE_ECC_KEYGEN
#define WOLFSSL_ECDSA_SET_K
#define ECC_USER_CURVES
#define HAVE_ECC192
#define HAVE_ECC224
#define HAVE_ECC256
#define HAVE_ECC384
#define HAVE_ECC521
#define WOLFSSL_KEY_GEN
#define WOLFSSL_PUBLIC_MP
#define WC_RNG_SEED_CB
#define FP_MAX_BITS 16384
#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT
#define NO_MD5
#define NO_DES3
#define NO_MD4
#define NO_DSA
#define NO_OLD_TLS
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME
#define NO_ERROR_STRINGS

#endif /* _FIPS_READY_USER_SETTINGS_H_ */
