#ifndef _NON_FIPS_USER_SETTINGS_H_
#define _NON_FIPS_USER_SETTINGS_H_

#ifndef _WIN32
#error This user_settings.h header is only designed for Windows
#endif

#define WOLFCRYPT_ONLY
#define WOLFSSL_AESGCM_STREAM
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_OFB
#define HAVE_CHACHA
#define HAVE_POLY1305
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHA224
#define WOLFSSL_NO_SHAKE256
#define NO_MD5
#define HAVE_HKDF
#define NO_OLD_TLS
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
#define HAVE_ED25519
#define HAVE_CURVE25519
#define WOLFSSL_KEY_GEN
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME
#define NO_ERROR_STRINGS
#define WOLFSSL_PUBLIC_MP
#define FP_MAX_BITS 16384
#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT

/* PKCS7 requirements */
#define HAVE_PKCS7
#define HAVE_AES_KEYWRAP
#define WOLFSSL_AES_DIRECT
#define HAVE_X963_KDF

#endif /* _NON_FIPS_USER_SETTINGS_H_ */
