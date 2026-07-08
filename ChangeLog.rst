wolfCrypt-py Release 5.9.2 (Jul 1, 2026)
==========================================

* Update to wolfSSL version 5.9.2
* Make t2b support other types
* Fix ChaCha20Poly1305 to be singleshot
* Fix padding of small ECC signatures
* ML-DSA: Add support for generating private key deterministically from seed
* ML-DSA: Add support for deterministic signing
* ML-DSA: Add support for signing and verifying with context
* ML-DSA: Signing without context is disabled by default.
  Note: this can be enabled by compiling the C-library with `--enable-mldsa=yes,no-ctx`
* Drop support for end-of-life Python versions (<= 3.9)
* Add extra nonce parameter to Random generator
* Add type annotations to utils and random
* Add pyproject.toml for modern Python packaging
* Fix AES-SIV silently mangling associated data
* Fix ChaCha decrypt stream state wiping on first call
* Fix Random AttributeError on builds without ML-KEM/ML-DSA
* Fix Ed448 ctx cdef to match wolfSSL header signature
* Fix wc_ecc_import_unsigned cdef to match wolfSSL header
* Fix wc_RsaPSS_Verify const qualifier in cdef
* Fix wc_GetPkcs8TraditionalOffset non-const bytes handling
* Validate raw element lengths in EccPublic/EccPrivate.decode_key_raw
* Improve WolfCryptError exception to include error return value
* Code modernization: f-strings, remove unicode prefix, remove redundant code
* Fix issue in AES-GCM tag verification
* Address many small issues found by Fenrir
* Add reseed support to random number generator
* The RsaPublic key parameter is now mandatory as it is always needed by an internal function call.
* The `native_object` attribute of `Random` is now read-only.
* Add typing annotations.


wolfCrypt-py Release 5.8.4 (Jan 7, 2026)
==========================================

* Add support for HKDF
* Add support for AES-SIV
* Fix Windows build for ML-KEM, ML-DSA, and SHAKE
* Fix header parsing in build_ffi.py for feature detection logic
* Improve support for minimal wolfSSL configurations
* Fix function availability detection for RSA and ASN features
* Detect ML-KEM availability for USE_LOCAL_WOLFSSL
* Update to wolfSSL version 5.8.4


wolfCrypt-py Release 5.8.2 (Jul 24, 2025)
==========================================

* Add support for ML-KEM
* Add support for ML-DSA
* Update to wolfSSL version 5.8.2

wolfCrypt-py Release 5.7.4 (Nov 13, 2024)
==========================================

* Add support for ChaCha20-Poly1305
* Update to wolfSSL version 5.7.4


wolfCrypt-py Release 5.7.2 (Sep 6, 2024)
==========================================

* Update to wolfSSL version 5.7.2


wolfCrypt-py Release 5.6.6 (Jan 23, 2024)
==========================================

* Update to wolfSSL version 5.6.6


wolfCrypt-py Release 5.6.0 (May 2, 2022)
==========================================

* Add user settings path for scripts/user_settings_asm.sh during cmake
* Update to wolfSSL version 5.6.0


wolfCrypt-py Release 5.5.4 (December 30, 2022)
==========================================

* Update to wolfSSL version 5.5.4

wolfCrypt-py Release 5.5.3 (November 7, 2022)
==========================================

* Add ChangeLog file
* Add optional hash_type parameter to RSA from_pem functions
* Improve the RSA PSS code
* Gate inclusion of wc_GenerateSeed in C wrapper on WC_RNG_SEED_CB_ENABLED
* Make several improvements to the CFFI build process
* Update to wolfSSL version 5.5.3


wolfCrypt-py Release 5.4.0 (July 13, 2022)
==========================================

New Features
------------

* Update to wolfCrypt 5.4.0 C library
* Add GitHub Actions support, remove Travis CI

Fixes
-----

* Fixups for PyPi
* Remove some of the CMake hack due to things moved into wolfSSL CMakeLists.txt

wolfCrypt-py Release 5.3.0 (May 10, 2022)
=========================================

New Features
------------

* Update to wolfCrypt 5.3.0
* Build completely refactored to be more Python-like and easier to use
* Added support for SHA3
* Added support for ChaCha stream cipher
* Add support for RSA private keys in PKCS #8 format
* Add module pwdbased.py and expose wc_PBKDF2
* Modifications to make wolfCrypt-py work with FIPS ready and FIPS v5
* Add support for ed448
* Add a pem_to_der function and support for PEM RSA keys
* Add signature generation and verification
* Enabled pwdbased by default
* Windows support added
* Added support for AES-CTR
* Add support for AES GCM streaming
* Add RSA OAEP and PSS padding
* Add get_aad() function

Fixes
-----

* Documentation improvements

