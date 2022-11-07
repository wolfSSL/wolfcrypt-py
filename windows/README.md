# Overview

This directory contains user_settings.h files that can be used to build wolfSSL
on Windows for use with wolfcrypt-py. non_fips/user_settings.h is, as the name
indicates, intended for non-FIPS builds. fips_ready/user_settings.h is for FIPS
Ready builds. non_fips/user_settings.h is used by build_ffi.py when building
wolfcrypt-py on Windows without USE_LOCAL_WOLFSSL. fips_ready/user_settings.h
isn't used by build_ffi.py.

## Non-FIPS

If building with our wolfssl64.sln Visual Studio solution, copy
non_fips\user_settings.h into IDE\WIN in the wolfSSL directory, overwriting the
existing user_settings.h. Build the solution, set the environment variable
USE_LOCAL_WOLFSSL to point to the wolfSSL directory, and proceed with the
wolfcrypt-py build/install (e.g. `pip install .` from the wolfcrypt-py
directory).

## FIPS Ready

The instructions are similar to the non-FIPS instructions. Copy
fips_ready\user_settings.h into IDE\WIN10. Build the IDE\WIN10\wolfssl-fips.sln
solution. Set the environment variable USE_LOCAL_WOLFSSL to point to the wolfSSL
directory, and proceed with the wolfcrypt-py build/install (e.g. `pip install .`
from the wolfcrypt-py directory).
