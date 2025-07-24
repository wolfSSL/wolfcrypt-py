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

