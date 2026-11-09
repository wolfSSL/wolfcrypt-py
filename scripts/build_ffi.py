# build_ffi.py
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

import os
import sys
import re
import subprocess
from contextlib import contextmanager
try:
    from distutils.util import get_platform
except ImportError:
    # Python >= 3.12 without setuptools' distutils shim (unit tests).
    from sysconfig import get_platform
from cffi import FFI
import shutil
from wolfcrypt._version import __wolfssl_version__ as version

def local_path(path):
    """ Return path relative to the root of this project
    """
    current = os.path.abspath(os.getcwd())
    return os.path.abspath(os.path.join(current, path))

WOLFSSL_SRC_PATH = local_path("lib/wolfssl")

def wolfssl_inc_dirs(local_wolfssl=None, fips=False):
    """Returns the wolfSSL include directories needed to build the CFFI.
    """
    include_paths = []
    if local_wolfssl:
        include_dir = os.path.join(local_wolfssl, "include")
        # If an include subdirectory exists under local_wolfssl, use that.
        # Otherwise, use local_wolfssl (e.g. local_wolfssl may point to a
        # wolfssl source code directory).
        if os.path.exists(include_dir):
            include_paths.append(include_dir)
        else:
            include_paths.append(local_wolfssl)
            if sys.platform == "win32":
                # Add the user_settings.h directory.
                if fips:
                    include_paths.append(os.path.join(local_wolfssl, "IDE",
                        "WIN10"))
                else:
                    include_paths.append(os.path.join(local_wolfssl, "IDE",
                        "WIN"))
    else:
        include_paths.append(os.path.join(WOLFSSL_SRC_PATH, get_platform(),
            version, "include"))
        if sys.platform == "win32":
            # Add the user_settings.h directory.
            include_paths.append(os.path.join(WOLFSSL_SRC_PATH, "build"))

    return include_paths

def wolfssl_lib_dir(local_wolfssl=None, fips=False):
    """Returns the directory containg the wolfSSL library.
    """
    lib_dir = None

    if local_wolfssl:
        lib_names = []
        if sys.platform == "win32":
            lib_names.append("wolfssl-fips.dll")
            lib_names.append("wolfssl.lib")
        else:
            lib_names.append("libwolfssl.a")
            lib_names.append("libwolfssl.so")

        found = False
        for root, _dirs, files in os.walk(local_wolfssl):
            for name in lib_names:
                if name in files:
                    lib_dir = root
                    found = True
                    break

            if found:
                break
    else:
        lib_dir = os.path.join(WOLFSSL_SRC_PATH, get_platform(), version, "lib")

    if not lib_dir:
        e = ("Unable to find wolfSSL library. If using USE_LOCAL_WOLFSSL, "
             "ensure wolfSSL has been built.")
        raise FileNotFoundError(e)

    return lib_dir

def call(cmd):
    print(f"Calling: '{cmd}' from working directory {os.getcwd()}")

    old_env = os.environ["PATH"]
    os.environ["PATH"] = f"{WOLFSSL_SRC_PATH}:{old_env}"
    subprocess.check_call(cmd, shell=True, env=os.environ)
    os.environ["PATH"] = old_env

@contextmanager
def chdir(new_path, mkdir=False):
    old_path = os.getcwd()

    if mkdir:
        try:
            os.mkdir(new_path)
        except OSError:
            pass

    try:
        yield os.chdir(new_path)
    finally:
        os.chdir(old_path)


def checkout_version(version):
    """ Ensure that we have the right version.
    """
    with chdir(WOLFSSL_SRC_PATH):
        current = ""
        try:
            current = subprocess.check_output(
                ["git", "describe", "--all", "--exact-match"]
            ).strip().decode().split('/')[-1]
        except subprocess.CalledProcessError:
            pass

        if current != version:
            tags = subprocess.check_output(
                ["git", "tag"]
            ).strip().decode().split("\n")

            if version != "master" and version not in tags:
                call(f"git fetch --depth=1 origin tag {version}")

            call(f"git checkout --force {version}")

            return True  # rebuild needed

    return False


def ensure_wolfssl_src(ref):
    """ Ensure that wolfssl sources are presents and up-to-date.
    """

    if not os.path.isdir("lib"):
        os.mkdir("lib")
        with chdir("lib"):
            subprocess.run(["git", "clone", "--depth=1", "https://github.com/wolfssl/wolfssl"])

    if not os.path.isdir(os.path.join(WOLFSSL_SRC_PATH, "wolfssl")):
        subprocess.run(["git", "submodule", "update", "--init", "--depth=1"])

    return checkout_version(version)


def make_flags(prefix, fips):
    """ Returns compilation flags.
    """
    if sys.platform == "win32":
        flags = []
        flags.append(f"-DCMAKE_INSTALL_PREFIX={prefix}")
        flags.append("-DWOLFSSL_CRYPT_TESTS=no")
        flags.append("-DWOLFSSL_EXAMPLES=no")
        flags.append("-DBUILD_SHARED_LIBS=no")
        flags.append("-DWOLFSSL_USER_SETTINGS=yes")
        if fips:
            flags.append("-DCMAKE_CXX_FLAGS=-I" + local_path("../IDE/WIN10"))
        else:
            flags.append("-DCMAKE_CXX_FLAGS=-I" + local_path("../IDE/WIN"))
        return " ".join(flags)
    else:
        flags = []

        # The static lib is linked into the shared extension.
        if get_platform().startswith("linux"):
            flags.append("CFLAGS=-fPIC")

        # install location
        flags.append(f"--prefix={prefix}")

        # crypt only, lib only
        flags.append("--enable-cryptonly")
        flags.append("--disable-crypttests")
        flags.append("--disable-shared")

        # symmetric ciphers
        flags.append("--enable-aes")
        flags.append("--enable-aesctr")
        flags.append("--enable-des3")
        flags.append("--enable-chacha")

        flags.append("--enable-aesgcm-stream")

        flags.append("--enable-aesgcm")
        flags.append("--enable-aessiv")

        # hashes and MACs
        flags.append("--enable-sha")
        flags.append("--enable-sha384")
        flags.append("--enable-sha512")
        flags.append("--enable-sha3")
        flags.append("--enable-hkdf")

        flags.append("--disable-md5")
        flags.append("--disable-sha224")
        flags.append("--enable-poly1305")

        # asymmetric ciphers
        flags.append("--enable-rsa")
        flags.append("--enable-rsapss")
        flags.append("--enable-ecc")
        flags.append("--enable-ed25519")
        flags.append("--enable-ed448")
        flags.append("--enable-curve25519")
        flags.append("--enable-keygen")

        flags.append("--disable-dh")

        # pwdbased
        flags.append("--enable-pwdbased")
        flags.append("--enable-pkcs7")

        # ML-KEM
        flags.append("--enable-mlkem")

        # ML-DSA (note: to be able to use the legacy option of signing without context, pass `yes,no-ctx` as argument)
        flags.append("--enable-mldsa=yes")

        # Crypto Callbacks
        flags.append("--enable-cryptocb")
        # Hash callbacks track per-object state across wc_*Copy and wc_*Free
        flags.append("--enable-cryptocbutils=copy,free")
        # flags.append("EXTRACPPFLAGS=-DDEBUG_CRYPTOCB")

        # disabling other configs enabled by default
        flags.append("--disable-oldtls")
        flags.append("--disable-oldnames")
        flags.append("--disable-extended-master")

        return " ".join(flags)


def make(configure_flags, fips=False):
    """ Create a release of wolfSSL C library
    """
    if sys.platform == 'win32':
        build_path = os.path.join(WOLFSSL_SRC_PATH, "build")
        if not os.path.isdir(build_path):
            os.mkdir(build_path)

        if not fips:
            shutil.copy(local_path("windows/non_fips/user_settings.h"),
                        build_path)
        else:
            raise Exception("Cannot build wolfSSL FIPS from git repo.")

        with chdir(build_path):
            call(f"cmake {configure_flags} ..")
            call("cmake --build . --config Release")
            call("cmake --install . --config Release")
    else:
        with chdir(WOLFSSL_SRC_PATH):
            call("git clean -fdX")

            try:
                call("./autogen.sh")
            except subprocess.CalledProcessError:
                call("libtoolize")
                call("./autogen.sh")

            call(f"./configure {configure_flags}")
            call("make")
            call("make install")

def get_libwolfssl():
    if sys.platform == "win32":
        libwolfssl_path = os.path.join(wolfssl_lib_dir(), "wolfssl.lib")
        if not os.path.exists(libwolfssl_path):
            return False
        else:
            return True
    else:
        libwolfssl_path = os.path.join(wolfssl_lib_dir(), "libwolfssl.a")
        if not os.path.exists(libwolfssl_path):
            libwolfssl_path = os.path.join(wolfssl_lib_dir(), "libwolfssl.so")
            if not os.path.exists(libwolfssl_path):
                return False
            else:
                return True
        else:
            return True

def generate_libwolfssl(fips):
    ensure_wolfssl_src(version)
    prefix = os.path.join(WOLFSSL_SRC_PATH, get_platform(), version)
    make(make_flags(prefix, fips))

def get_features(local_wolfssl, features):
    fips = False
    fips_file = None

    if local_wolfssl and sys.platform == "win32":
        # On Windows, we assume the local_wolfssl path is to a wolfSSL source
        # directory where the library has been built.
        fips_file = os.path.join(local_wolfssl, "wolfssl", "wolfcrypt",
            "fips.h")
    elif local_wolfssl:
        # On non-Windows platforms, first assume local_wolfssl is an
        # installation directory with an include subdirectory.
        fips_file = os.path.join(local_wolfssl, "include", "wolfssl",
            "wolfcrypt", "fips.h")
        if not os.path.exists(fips_file):
            # Try assuming local_wolfssl is a wolfSSL source directory.
            fips_file = os.path.join(local_wolfssl, "wolfssl", "wolfcrypt",
                "fips.h")

    if fips_file and os.path.exists(fips_file):
        with open(fips_file) as f:
            contents = f.read()
            if not contents.isspace():
                fips = True

    include_dirs = wolfssl_inc_dirs(local_wolfssl, fips)
    for d in include_dirs:
        if not os.path.exists(d):
            e = f"Invalid wolfSSL include dir: {d}"
            raise FileNotFoundError(e)

    return detect_features(feature_macros(include_dirs), features, fips, include_dirs)

PROBE_DEFINED = "WOLFCRYPT_PY_DEFINED"
PROBE_VALUE = "WOLFCRYPT_PY_VALUE"
# Macros whose values detect_features() reads.
VALUE_MACROS = ("WOLFSSL_MIN_AUTH_TAG_SZ", "HAVE_FIPS_VERSION")

def header_macro_names(include_dirs):
    """Return the names #defined in the headers the extension can include."""
    names = set()
    for d in include_dirs:
        paths = [os.path.join(d, name) for name in os.listdir(d) if name.endswith(".h")]
        for root, _dirs, files in os.walk(os.path.join(d, "wolfssl")):
            paths += [os.path.join(root, name) for name in files if name.endswith(".h")]
        for path in paths:
            with open(path, errors="replace") as f:
                names.update(re.findall(r"^\s*#\s*define\s+(\w+)", f.read(), re.MULTILINE))
    return names

def probe_source(names):
    """Return C source that marks which of names the extension sees defined."""
    lines = [source_includes()]
    for name in sorted(names):
        lines += [f"#ifdef {name}", f'{PROBE_DEFINED} "{name}"']
        if name in VALUE_MACROS:
            lines.append(f'{PROBE_VALUE} "{name}" {name}')
        lines.append("#endif")
    return "\n".join(lines) + "\n"

def preprocess(path, include_dirs):
    """Run the C preprocessor of the extension build and return its output."""
    try:
        import setuptools  # noqa: F401  # provides distutils on Python >= 3.12
    except ImportError:
        pass
    from distutils.ccompiler import new_compiler
    from distutils.sysconfig import customize_compiler

    compiler = new_compiler()
    customize_compiler(compiler)
    if compiler.compiler_type == "msvc":
        compiler.initialize()
        cmd = [compiler.cc, "/nologo", "/EP"] + [f"/I{d}" for d in include_dirs]
    else:
        cmd = list(compiler.preprocessor or compiler.compiler[:1] + ["-E"])
        cmd += [f"-I{d}" for d in include_dirs]
    result = subprocess.run(cmd + [path], capture_output=True, text=True)
    if result.returncode != 0:
        e = f"Preprocessing the wolfSSL headers failed:\n{result.stderr}"
        raise RuntimeError(e)
    return result.stdout

def feature_macros(include_dirs):
    """Return {name: value} of the macros the extension compile sees.

    The compiler reads options.h or user_settings.h and settings.h, so #if
    blocks, #undef and the macros settings.h derives count as in the build.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "wolfcrypt_py_probe.c")
        with open(path, "w") as f:
            f.write(probe_source(header_macro_names(include_dirs)))
        output = preprocess(path, include_dirs)

    macros = dict.fromkeys(re.findall(rf'^\s*{PROBE_DEFINED}\s+"(\w+)"', output, re.MULTILINE), "")
    for name, value in re.findall(rf'^\s*{PROBE_VALUE}\s+"(\w+)"[ \t]*(.*)$', output, re.MULTILINE):
        macros[name] = value.strip()
    return macros

def macro_int(macros, name):
    """Return the integer value of macro name, or None."""
    match = re.match(r"[(\s]*(\d+)", macros.get(name, ""))
    return int(match.group(1)) if match else None

def detect_features(macros, features, fips=False, include_dirs=()):
    """Set features from the macros the extension compile sees."""
    def defined(name):
        return name in macros

    features["MPAPI"] = 1 if defined("WOLFSSL_PUBLIC_MP") else 0
    features["SHA"] = 0 if defined("NO_SHA") else 1
    features["SHA256"] = 0 if defined("NO_SHA256") else 1
    features["SHA384"] = 1 if defined("WOLFSSL_SHA384") else 0
    features["SHA512"] = 1 if defined("WOLFSSL_SHA512") else 0
    features["SHA3"] = 1 if defined("WOLFSSL_SHA3") else 0
    features["DES3"] = 0 if defined("NO_DES3") else 1
    features["AES"] = 0 if defined("NO_AES") else 1
    features["AES_SIV"] = 1 if defined("WOLFSSL_AES_SIV") else 0
    features["CHACHA"] = 1 if defined("HAVE_CHACHA") else 0
    features["HMAC"] = 0 if defined("NO_HMAC") else 1
    features["RSA"] = 0 if defined("NO_RSA") else 1
    features["ECC_TIMING_RESISTANCE"] = 1 if defined("ECC_TIMING_RESISTANT") else 0
    features["RSA_BLINDING"] = 1 if defined("WC_RSA_BLINDING") else 0
    features["ECC"] = 1 if defined("HAVE_ECC") else 0
    features["ED25519"] = 1 if defined("HAVE_ED25519") else 0
    features["ED448"] = 1 if defined("HAVE_ED448") else 0
    features["KEYGEN"] = 1 if defined("WOLFSSL_KEY_GEN") else 0
    features["PWDBASED"] = 0 if defined("NO_PWDBASED") else 1
    features["ERROR_STRINGS"] = 0 if defined("NO_ERROR_STRINGS") else 1
    features["ASN"] = 0 if defined("NO_ASN") else 1
    features["WC_RNG_SEED_CB"] = 1 if defined("WC_RNG_SEED_CB") else 0
    features["AESGCM_STREAM"] = 1 if defined("WOLFSSL_AESGCM_STREAM") else 0
    min_auth_tag_sz = macro_int(macros, "WOLFSSL_MIN_AUTH_TAG_SZ")
    features["MIN_AUTH_TAG_SZ"] = 12 if min_auth_tag_sz is None else min_auth_tag_sz
    features["RSA_PSS"] = 1 if defined("WC_RSA_PSS") else 0
    features["CHACHA20_POLY1305"] = 1 if (defined("HAVE_CHACHA") and defined("HAVE_POLY1305")) else 0
    features["ML_DSA"] = 1 if (defined("HAVE_DILITHIUM") or defined("WOLFSSL_HAVE_MLDSA")) else 0
    # dilithium.h maps the legacy WOLFSSL_DILITHIUM_<gate> names to WOLFSSL_MLDSA_<gate>.
    features["ML_DSA_NO_CTX"] = 1 if (defined("WOLFSSL_MLDSA_NO_CTX")
        or defined("WOLFSSL_MLDSA_FIPS204_DRAFT")) else 0
    features["ML_KEM"] = 1 if defined("WOLFSSL_HAVE_MLKEM") else 0
    # hmac.h and hmac.c provide HKDF only without NO_HMAC.
    features["HKDF"] = 1 if defined("HAVE_HKDF") and features["HMAC"] else 0
    features["HASHDRBG"] = 1 if defined("HAVE_HASHDRBG") else 0
    features["CRYPTO_CB"] = 1 if defined("WOLF_CRYPTO_CB") else 0
    features["CRYPTO_CB_COPY"] = 1 if defined("WOLF_CRYPTO_CB_COPY") else 0
    features["CRYPTO_CB_FREE"] = 1 if defined("WOLF_CRYPTO_CB_FREE") else 0
    # wc_HmacCopy was added in wolfSSL 5.9.0 and has no feature define.
    features["HMAC_COPY"] = 0
    if features["HMAC"]:
        for d in include_dirs:
            hmac_h = os.path.join(d, "wolfssl", "wolfcrypt", "hmac.h")
            if os.path.exists(hmac_h):
                with open(hmac_h) as f:
                    if "wc_HmacCopy" in f.read():
                        features["HMAC_COPY"] = 1
    # random.h replaces the RNG API with macros under WC_NO_RNG. random.c and
    # rsa.c then build no DRBG, seed callback or RSA blinding functions.
    features["RNG"] = 0 if defined("WC_NO_RNG") else 1
    if not features["RNG"]:
        features["HASHDRBG"] = 0
        features["WC_RNG_SEED_CB"] = 0
        features["RSA_BLINDING"] = 0
    # aes.h declares wc_AesCtrEncrypt only with WOLFSSL_AES_COUNTER.
    features["AES_CTR"] = 1 if features["AES"] and defined("WOLFSSL_AES_COUNTER") else 0
    features["AES_CBC"] = 1 if features["AES"] and defined("HAVE_AES_CBC") else 0
    features["AES_DECRYPT"] = 1 if features["AES"] and defined("HAVE_AES_DECRYPT") else 0
    # aes.c builds streaming GCM decryption only with HAVE_AES_DECRYPT or HAVE_AESGCM_DECRYPT.
    features["AESGCM_STREAM_DECRYPT"] = 1 if features["AES"] and features["AESGCM_STREAM"] and (
        features["AES_DECRYPT"] or defined("HAVE_AESGCM_DECRYPT")) else 0
    # sha3.c builds each SHA-3 size unless WOLFSSL_NOSHA3_<bits>.
    for bits in (224, 256, 384, 512):
        features[f"SHA3_{bits}"] = 1 if features["SHA3"] and not defined(f"WOLFSSL_NOSHA3_{bits}") else 0
    # pwdbased.c builds wc_PBKDF2 only with HAVE_PBKDF2 and without NO_HMAC.
    features["PBKDF2"] = 1 if features["PWDBASED"] and features["HMAC"] and defined("HAVE_PBKDF2") else 0
    # asn.c builds the PEM/DER conversions only with certificate support.
    features["CERTS"] = 1 if features["ASN"] and not defined("NO_CERTS") else 0
    features["PEM_TO_DER"] = 1 if features["CERTS"] and defined("WOLFSSL_PEM_TO_DER") else 0
    features["DER_TO_PEM"] = 1 if features["CERTS"] and defined("WOLFSSL_DER_TO_PEM") else 0
    # asn.c builds wc_GetPkcs8TraditionalOffset only with HAVE_PKCS8.
    features["PKCS8"] = 1 if features["ASN"] and defined("HAVE_PKCS8") else 0
    # rsa.c leaves out RSA operations for the subset macros set by
    # --enable-rsapub, --enable-rsavfy and --disable-oaep.
    rsa_public_only = defined("WOLFSSL_RSA_PUBLIC_ONLY")
    rsa_verify_only = defined("WOLFSSL_RSA_VERIFY_ONLY")
    features["RSA_ENCRYPT"] = 1 if features["RSA"] and not rsa_verify_only else 0
    features["RSA_PRIVATE"] = 1 if features["RSA"] and not rsa_public_only else 0
    features["RSA_SIGN"] = 1 if features["RSA_PRIVATE"] and not rsa_verify_only else 0
    features["RSA_VERIFY"] = 1 if features["RSA"] and not defined("WOLFSSL_RSA_VERIFY_INLINE") else 0
    features["RSA_OAEP"] = 1 if features["RSA"] and not defined("WC_NO_RSA_OAEP") else 0
    # settings.h derives HAVE_<alg>_<op> for the ECC and EdDSA operations.
    for op in ("SIGN", "VERIFY", "DHE", "KEY_IMPORT", "KEY_EXPORT"):
        features[f"ECC_{op}"] = 1 if features["ECC"] and defined(f"HAVE_ECC_{op}") else 0
    for op in ("MAKE_KEY", "SIGN", "VERIFY", "KEY_IMPORT", "KEY_EXPORT"):
        features[f"ED25519_{op}"] = 1 if features["ED25519"] and defined(f"HAVE_ED25519_{op}") else 0
    for op in ("SIGN", "VERIFY", "KEY_IMPORT", "KEY_EXPORT"):
        features[f"ED448_{op}"] = 1 if features["ED448"] and defined(f"HAVE_ED448_{op}") else 0
    # wc_mlkem.c builds each ML-KEM operation unless WOLFSSL_MLKEM_NO_<op>.
    # wc_mlkem.h maps the legacy WOLFSSL_KYBER_NO_<op> names to these.
    for op in ("MAKE_KEY", "ENCAPSULATE", "DECAPSULATE"):
        features[f"ML_KEM_{op}"] = 1 if features["ML_KEM"] and not defined(f"WOLFSSL_MLKEM_NO_{op}") else 0
    # dilithium.h derives the ML-DSA operations and key parts.
    ml_dsa = features["ML_DSA"]
    features["ML_DSA_MAKE_KEY"] = 1 if ml_dsa and not defined("WOLFSSL_MLDSA_NO_MAKE_KEY") else 0
    features["ML_DSA_SIGN"] = 1 if ml_dsa and not defined("WOLFSSL_MLDSA_NO_SIGN") else 0
    features["ML_DSA_VERIFY"] = 1 if ml_dsa and not defined("WOLFSSL_MLDSA_NO_VERIFY") else 0
    features["ML_DSA_PUBLIC_KEY"] = 1 if ml_dsa and defined("WOLFSSL_MLDSA_PUBLIC_KEY") else 0
    features["ML_DSA_PRIVATE_KEY"] = 1 if ml_dsa and defined("WOLFSSL_MLDSA_PRIVATE_KEY") else 0

    if defined("HAVE_FIPS"):
        if not fips:
            e = "fips.c empty but HAVE_FIPS defined."
            raise RuntimeError(e)

        features["FIPS"] = 1
        fips_version = macro_int(macros, "HAVE_FIPS_VERSION")
        if fips_version is None:
            e = "Saw #define HAVE_FIPS but no FIPS version found."
            raise RuntimeError(e)
        features["FIPS_VERSION"] = fips_version

    return features

def build_ffi(local_wolfssl, features):
    cffi_include_dirs = wolfssl_inc_dirs(local_wolfssl, features["FIPS"])
    cffi_libraries = []

    if sys.platform == 'win32':
        if features["FIPS"]:
            # To use the CFFI library, we need wolfssl-fips.dll. It should exist
            # alongside the .pyd created by CFFI, so we copy it over here.
            shutil.copy(os.path.join(wolfssl_lib_dir(local_wolfssl,
                features["FIPS"]), "wolfssl-fips.dll"),
                local_path("wolfcrypt/"))
            cffi_libraries.append("wolfssl-fips")
        else:
            cffi_libraries.append("wolfssl")

        # Needed for WIN32 functions in random.c.
        cffi_libraries.append("Advapi32")
    else:
        cffi_libraries.append("wolfssl")

    ffibuilder.set_source( "wolfcrypt._ffi", make_source(features),
        include_dirs=cffi_include_dirs,
        library_dirs=[wolfssl_lib_dir(local_wolfssl, features["FIPS"])],
        libraries=cffi_libraries)

    ffibuilder.cdef(make_cdef(features))

def source_includes():
    """Return the wolfSSL #include lines of the extension source."""
    includes_string = ""

    if sys.platform == 'win32':
        includes_string += """
        #ifndef WOLFSSL_USER_SETTINGS
        #define WOLFSSL_USER_SETTINGS
        #endif

        #include \"user_settings.h\"\n
        """
    else:
        includes_string += "#include  <wolfssl/options.h>\n"

    includes_string += """
        #include <wolfssl/wolfcrypt/settings.h>
        #include <wolfssl/wolfcrypt/error-crypt.h>

        #include <wolfssl/wolfcrypt/sha.h>
        #include <wolfssl/wolfcrypt/sha256.h>
        #include <wolfssl/wolfcrypt/sha512.h>
        #include <wolfssl/wolfcrypt/sha3.h>

        #include <wolfssl/wolfcrypt/hmac.h>

        #include <wolfssl/wolfcrypt/aes.h>
        #include <wolfssl/wolfcrypt/chacha.h>
        #include <wolfssl/wolfcrypt/des3.h>
        #include <wolfssl/wolfcrypt/asn.h>
        #include <wolfssl/wolfcrypt/pwdbased.h>

        #include <wolfssl/wolfcrypt/random.h>

        #include <wolfssl/wolfcrypt/rsa.h>
        #include <wolfssl/wolfcrypt/ecc.h>
        #include <wolfssl/wolfcrypt/ed25519.h>
        #include <wolfssl/wolfcrypt/ed448.h>
        #include <wolfssl/wolfcrypt/curve25519.h>
        #include <wolfssl/wolfcrypt/poly1305.h>
        #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
        #include <wolfssl/wolfcrypt/wc_mlkem.h>
        #include <wolfssl/wolfcrypt/wc_mldsa.h>
        #include <wolfssl/wolfcrypt/cryptocb.h>
    """

    return includes_string

def make_source(features):
    """Return the C source passed to set_source()."""
    includes_string = source_includes()

    init_source_string = f"""
        #ifdef __cplusplus
        extern "C" {{
        #endif
        {includes_string}
        #ifdef __cplusplus
        }}
        #endif

        int ERROR_STRINGS_ENABLED = {features["ERROR_STRINGS"]};
        int MPAPI_ENABLED = {features["MPAPI"]};
        int SHA_ENABLED = {features["SHA"]};
        int SHA256_ENABLED = {features["SHA256"]};
        int SHA384_ENABLED = {features["SHA384"]};
        int SHA512_ENABLED = {features["SHA512"]};
        int SHA3_ENABLED = {features["SHA3"]};
        int DES3_ENABLED = {features["DES3"]};
        int AES_ENABLED = {features["AES"]};
        int AES_SIV_ENABLED = {features["AES_SIV"]};
        int CHACHA_ENABLED = {features["CHACHA"]};
        int HMAC_ENABLED = {features["HMAC"]};
        int RSA_ENABLED = {features["RSA"]};
        int RSA_BLINDING_ENABLED = {features["RSA_BLINDING"]};
        int ECC_TIMING_RESISTANCE_ENABLED = {features["ECC_TIMING_RESISTANCE"]};
        int ECC_ENABLED = {features["ECC"]};
        int ED25519_ENABLED = {features["ED25519"]};
        int ED448_ENABLED = {features["ED448"]};
        int KEYGEN_ENABLED = {features["KEYGEN"]};
        int PWDBASED_ENABLED = {features["PWDBASED"]};
        int FIPS_ENABLED = {features["FIPS"]};
        int FIPS_VERSION = {features["FIPS_VERSION"]};
        int ASN_ENABLED = {features["ASN"]};
        int CERTS_ENABLED = {features["CERTS"]};
        int WC_RNG_SEED_CB_ENABLED = {features["WC_RNG_SEED_CB"]};
        int AESGCM_STREAM_ENABLED = {features["AESGCM_STREAM"]};
        int MIN_AUTH_TAG_SZ = {features["MIN_AUTH_TAG_SZ"]};
        int RSA_PSS_ENABLED = {features["RSA_PSS"]};
        int CHACHA20_POLY1305_ENABLED = {features["CHACHA20_POLY1305"]};
        int ML_KEM_ENABLED = {features["ML_KEM"]};
        int ML_DSA_ENABLED = {features["ML_DSA"]};
        int ML_DSA_NO_CTX_ENABLED = {features["ML_DSA_NO_CTX"]};
        int HKDF_ENABLED = {features["HKDF"]};
        int HASHDRBG_ENABLED = {features["HASHDRBG"]};
        int CRYPTO_CB_ENABLED = {features["CRYPTO_CB"]};
        int CRYPTO_CB_COPY_ENABLED = {features["CRYPTO_CB_COPY"]};
        int CRYPTO_CB_FREE_ENABLED = {features["CRYPTO_CB_FREE"]};
        int HMAC_COPY_ENABLED = {features["HMAC_COPY"]};
        int AES_CTR_ENABLED = {features["AES_CTR"]};
        int AES_CBC_ENABLED = {features["AES_CBC"]};
        int AES_DECRYPT_ENABLED = {features["AES_DECRYPT"]};
        int AESGCM_STREAM_DECRYPT_ENABLED = {features["AESGCM_STREAM_DECRYPT"]};
        int SHA3_224_ENABLED = {features["SHA3_224"]};
        int SHA3_256_ENABLED = {features["SHA3_256"]};
        int SHA3_384_ENABLED = {features["SHA3_384"]};
        int SHA3_512_ENABLED = {features["SHA3_512"]};
        int PBKDF2_ENABLED = {features["PBKDF2"]};
        int PEM_TO_DER_ENABLED = {features["PEM_TO_DER"]};
        int DER_TO_PEM_ENABLED = {features["DER_TO_PEM"]};
        int PKCS8_ENABLED = {features["PKCS8"]};
        int RNG_ENABLED = {features["RNG"]};
        int RSA_ENCRYPT_ENABLED = {features["RSA_ENCRYPT"]};
        int RSA_PRIVATE_ENABLED = {features["RSA_PRIVATE"]};
        int RSA_SIGN_ENABLED = {features["RSA_SIGN"]};
        int RSA_VERIFY_ENABLED = {features["RSA_VERIFY"]};
        int RSA_OAEP_ENABLED = {features["RSA_OAEP"]};
        int ECC_SIGN_ENABLED = {features["ECC_SIGN"]};
        int ECC_VERIFY_ENABLED = {features["ECC_VERIFY"]};
        int ECC_DHE_ENABLED = {features["ECC_DHE"]};
        int ECC_KEY_IMPORT_ENABLED = {features["ECC_KEY_IMPORT"]};
        int ECC_KEY_EXPORT_ENABLED = {features["ECC_KEY_EXPORT"]};
        int ED25519_MAKE_KEY_ENABLED = {features["ED25519_MAKE_KEY"]};
        int ED25519_SIGN_ENABLED = {features["ED25519_SIGN"]};
        int ED25519_VERIFY_ENABLED = {features["ED25519_VERIFY"]};
        int ED25519_KEY_IMPORT_ENABLED = {features["ED25519_KEY_IMPORT"]};
        int ED25519_KEY_EXPORT_ENABLED = {features["ED25519_KEY_EXPORT"]};
        int ED448_SIGN_ENABLED = {features["ED448_SIGN"]};
        int ED448_VERIFY_ENABLED = {features["ED448_VERIFY"]};
        int ED448_KEY_IMPORT_ENABLED = {features["ED448_KEY_IMPORT"]};
        int ED448_KEY_EXPORT_ENABLED = {features["ED448_KEY_EXPORT"]};
        int ML_KEM_MAKE_KEY_ENABLED = {features["ML_KEM_MAKE_KEY"]};
        int ML_KEM_ENCAPSULATE_ENABLED = {features["ML_KEM_ENCAPSULATE"]};
        int ML_KEM_DECAPSULATE_ENABLED = {features["ML_KEM_DECAPSULATE"]};
        int ML_DSA_MAKE_KEY_ENABLED = {features["ML_DSA_MAKE_KEY"]};
        int ML_DSA_SIGN_ENABLED = {features["ML_DSA_SIGN"]};
        int ML_DSA_VERIFY_ENABLED = {features["ML_DSA_VERIFY"]};
        int ML_DSA_PUBLIC_KEY_ENABLED = {features["ML_DSA_PUBLIC_KEY"]};
        int ML_DSA_PRIVATE_KEY_ENABLED = {features["ML_DSA_PRIVATE_KEY"]};
    """

    return init_source_string

def make_cdef(features):
    """Return the cdef for the given features."""
    # TODO: change cdef to cdef.
    # cdef = ""
    cdef = """
        extern int ERROR_STRINGS_ENABLED;
        extern int MPAPI_ENABLED;
        extern int SHA_ENABLED;
        extern int SHA256_ENABLED;
        extern int SHA384_ENABLED;
        extern int SHA512_ENABLED;
        extern int SHA3_ENABLED;
        extern int DES3_ENABLED;
        extern int AES_ENABLED;
        extern int AES_SIV_ENABLED;
        extern int CHACHA_ENABLED;
        extern int HMAC_ENABLED;
        extern int RSA_ENABLED;
        extern int RSA_BLINDING_ENABLED;
        extern int ECC_TIMING_RESISTANCE_ENABLED;
        extern int ECC_ENABLED;
        extern int ED25519_ENABLED;
        extern int ED448_ENABLED;
        extern int KEYGEN_ENABLED;
        extern int PWDBASED_ENABLED;
        extern int FIPS_ENABLED;
        extern int FIPS_VERSION;
        extern int ASN_ENABLED;
        extern int CERTS_ENABLED;
        extern int WC_RNG_SEED_CB_ENABLED;
        extern int AESGCM_STREAM_ENABLED;
        extern int MIN_AUTH_TAG_SZ;
        extern int RSA_PSS_ENABLED;
        extern int CHACHA20_POLY1305_ENABLED;
        extern int ML_KEM_ENABLED;
        extern int ML_DSA_ENABLED;
        extern int ML_DSA_NO_CTX_ENABLED;
        extern int HKDF_ENABLED;
        extern int HASHDRBG_ENABLED;
        extern int CRYPTO_CB_ENABLED;
        extern int CRYPTO_CB_COPY_ENABLED;
        extern int CRYPTO_CB_FREE_ENABLED;
        extern int HMAC_COPY_ENABLED;

        static const int INVALID_DEVID;
        static const int WC_HW_E;
        static const int CRYPTOCB_UNAVAILABLE;
        extern int AES_CTR_ENABLED;
        extern int AES_CBC_ENABLED;
        extern int AES_DECRYPT_ENABLED;
        extern int AESGCM_STREAM_DECRYPT_ENABLED;
        extern int SHA3_224_ENABLED;
        extern int SHA3_256_ENABLED;
        extern int SHA3_384_ENABLED;
        extern int SHA3_512_ENABLED;
        extern int PBKDF2_ENABLED;
        extern int PEM_TO_DER_ENABLED;
        extern int DER_TO_PEM_ENABLED;
        extern int PKCS8_ENABLED;
        extern int RNG_ENABLED;
        extern int RSA_ENCRYPT_ENABLED;
        extern int RSA_PRIVATE_ENABLED;
        extern int RSA_SIGN_ENABLED;
        extern int RSA_VERIFY_ENABLED;
        extern int RSA_OAEP_ENABLED;
        extern int ECC_SIGN_ENABLED;
        extern int ECC_VERIFY_ENABLED;
        extern int ECC_DHE_ENABLED;
        extern int ECC_KEY_IMPORT_ENABLED;
        extern int ECC_KEY_EXPORT_ENABLED;
        extern int ED25519_MAKE_KEY_ENABLED;
        extern int ED25519_SIGN_ENABLED;
        extern int ED25519_VERIFY_ENABLED;
        extern int ED25519_KEY_IMPORT_ENABLED;
        extern int ED25519_KEY_EXPORT_ENABLED;
        extern int ED448_SIGN_ENABLED;
        extern int ED448_VERIFY_ENABLED;
        extern int ED448_KEY_IMPORT_ENABLED;
        extern int ED448_KEY_EXPORT_ENABLED;
        extern int ML_KEM_MAKE_KEY_ENABLED;
        extern int ML_KEM_ENCAPSULATE_ENABLED;
        extern int ML_KEM_DECAPSULATE_ENABLED;
        extern int ML_DSA_MAKE_KEY_ENABLED;
        extern int ML_DSA_SIGN_ENABLED;
        extern int ML_DSA_VERIFY_ENABLED;
        extern int ML_DSA_PUBLIC_KEY_ENABLED;
        extern int ML_DSA_PRIVATE_KEY_ENABLED;

        typedef unsigned char byte;
        typedef unsigned int word32;

        typedef struct { ...; } WC_RNG;
        typedef struct { ...; } OS_Seed;

        int wolfCrypt_Init(void);
    """
    if features["RNG"]:
        cdef += """
        int wc_InitRng(WC_RNG*);
        int wc_InitRngNonce(WC_RNG*, byte*, word32);
        int wc_InitRngNonce_ex(WC_RNG*, byte*, word32, void*, int);
        int wc_RNG_GenerateBlock(WC_RNG*, byte*, word32);
        int wc_RNG_GenerateByte(WC_RNG*, byte*);
        int wc_FreeRng(WC_RNG*);
        """
    if features["HASHDRBG"]:
        cdef += """
        int wc_RNG_DRBG_Reseed(WC_RNG*, const byte*, word32);
        """

    if features["ERROR_STRINGS"]:
        cdef += """
        static const int WC_FAILURE;

        static const int MAX_CODE_E;
        static const int WC_FIRST_E;

        static const int WC_SPAN1_FIRST_E;

        static const int MP_MEM;
        static const int MP_VAL;
        static const int MP_WOULDBLOCK;

        static const int MP_NOT_INF;

        static const int OPEN_RAN_E;
        static const int READ_RAN_E;
        static const int WINCRYPT_E;
        static const int CRYPTGEN_E;
        static const int RAN_BLOCK_E;
        static const int BAD_MUTEX_E;
        static const int WC_TIMEOUT_E;
        static const int WC_PENDING_E;
        static const int WC_NO_PENDING_E;

        static const int MP_INIT_E;
        static const int MP_READ_E;
        static const int MP_EXPTMOD_E;
        static const int MP_TO_E;
        static const int MP_SUB_E;
        static const int MP_ADD_E;
        static const int MP_MUL_E;
        static const int MP_MULMOD_E;
        static const int MP_MOD_E;
        static const int MP_INVMOD_E;
        static const int MP_CMP_E;
        static const int MP_ZERO_E;

        static const int AES_EAX_AUTH_E;
        static const int KEY_EXHAUSTED_E;
        static const int MEMORY_E;
        static const int VAR_STATE_CHANGE_E;
        static const int FIPS_DEGRADED_E;

        static const int FIPS_CODE_SZ_E;
        static const int FIPS_DATA_SZ_E;

        static const int RSA_WRONG_TYPE_E;
        static const int RSA_BUFFER_E;
        static const int BUFFER_E;
        static const int ALGO_ID_E;
        static const int PUBLIC_KEY_E;
        static const int DATE_E;
        static const int SUBJECT_E;
        static const int ISSUER_E;
        static const int CA_TRUE_E;
        static const int EXTENSIONS_E;

        static const int ASN_PARSE_E;
        static const int ASN_VERSION_E;
        static const int ASN_GETINT_E;
        static const int ASN_RSA_KEY_E;
        static const int ASN_OBJECT_ID_E;
        static const int ASN_TAG_NULL_E;
        static const int ASN_EXPECT_0_E;
        static const int ASN_BITSTR_E;
        static const int ASN_UNKNOWN_OID_E;
        static const int ASN_DATE_SZ_E;
        static const int ASN_BEFORE_DATE_E;
        static const int ASN_AFTER_DATE_E;
        static const int ASN_SIG_OID_E;
        static const int ASN_TIME_E;
        static const int ASN_INPUT_E;
        static const int ASN_SIG_CONFIRM_E;
        static const int ASN_SIG_HASH_E;
        static const int ASN_SIG_KEY_E;
        static const int ASN_DH_KEY_E;
        static const int KDF_SRTP_KAT_FIPS_E;
        static const int ASN_CRIT_EXT_E;
        static const int ASN_ALT_NAME_E;
        static const int ASN_NO_PEM_HEADER;
        static const int ED25519_KAT_FIPS_E;
        static const int ED448_KAT_FIPS_E;
        static const int PBKDF2_KAT_FIPS_E;
        static const int WC_KEY_MISMATCH_E;

        static const int ECC_BAD_ARG_E;
        static const int ASN_ECC_KEY_E;
        static const int ECC_CURVE_OID_E;
        static const int BAD_FUNC_ARG;
        static const int NOT_COMPILED_IN;
        static const int UNICODE_SIZE_E;
        static const int NO_PASSWORD;
        static const int ALT_NAME_E;
        static const int BAD_OCSP_RESPONDER;
        static const int CRL_CERT_DATE_ERR;

        static const int AES_GCM_AUTH_E;
        static const int AES_CCM_AUTH_E;

        static const int ASYNC_INIT_E;

        static const int COMPRESS_INIT_E;
        static const int COMPRESS_E;
        static const int DECOMPRESS_INIT_E;
        static const int DECOMPRESS_E;

        static const int BAD_ALIGN_E;
        static const int ASN_NO_SIGNER_E;
        static const int ASN_CRL_CONFIRM_E;
        static const int ASN_CRL_NO_SIGNER_E;
        static const int ASN_OCSP_CONFIRM_E;

        static const int BAD_STATE_E;
        static const int BAD_PADDING_E;

        static const int REQ_ATTRIBUTE_E;

        static const int PKCS7_OID_E;
        static const int PKCS7_RECIP_E;
        static const int FIPS_NOT_ALLOWED_E;
        static const int ASN_NAME_INVALID_E;

        static const int RNG_FAILURE_E;
        static const int HMAC_MIN_KEYLEN_E;
        static const int RSA_PAD_E;
        static const int LENGTH_ONLY_E;

        static const int IN_CORE_FIPS_E;
        static const int AES_KAT_FIPS_E;
        static const int DES3_KAT_FIPS_E;
        static const int HMAC_KAT_FIPS_E;
        static const int RSA_KAT_FIPS_E;
        static const int DRBG_KAT_FIPS_E;
        static const int DRBG_CONT_FIPS_E;
        static const int AESGCM_KAT_FIPS_E;
        static const int THREAD_STORE_KEY_E;
        static const int THREAD_STORE_SET_E;

        static const int MAC_CMP_FAILED_E;
        static const int IS_POINT_E;
        static const int ECC_INF_E;
        static const int ECC_PRIV_KEY_E;
        static const int ECC_OUT_OF_RANGE_E;

        static const int SRP_CALL_ORDER_E;
        static const int SRP_VERIFY_E;
        static const int SRP_BAD_KEY_E;

        static const int ASN_NO_SKID;
        static const int ASN_NO_AKID;
        static const int ASN_NO_KEYUSAGE;
        static const int SKID_E;
        static const int AKID_E;
        static const int KEYUSAGE_E;
        static const int CERTPOLICIES_E;

        static const int WC_INIT_E;
        static const int SIG_VERIFY_E;
        static const int BAD_COND_E;
        static const int SIG_TYPE_E;
        static const int HASH_TYPE_E;

        static const int FIPS_INVALID_VER_E;

        static const int WC_KEY_SIZE_E;
        static const int ASN_COUNTRY_SIZE_E;
        static const int MISSING_RNG_E;
        static const int ASN_PATHLEN_SIZE_E;
        static const int ASN_PATHLEN_INV_E;

        static const int BAD_KEYWRAP_ALG_E;
        static const int BAD_KEYWRAP_IV_E;
        static const int WC_CLEANUP_E;
        static const int ECC_CDH_KAT_FIPS_E;
        static const int DH_CHECK_PUB_E;
        static const int BAD_PATH_ERROR;

        static const int ASYNC_OP_E;

        static const int ECC_PRIVATEONLY_E;
        static const int EXTKEYUSAGE_E;
        static const int WC_HW_WAIT_E;

        static const int PSS_SALTLEN_E;
        static const int PRIME_GEN_E;
        static const int BER_INDEF_E;
        static const int RSA_OUT_OF_RANGE_E;
        static const int RSAPSS_PAT_FIPS_E;
        static const int ECDSA_PAT_FIPS_E;
        static const int DH_KAT_FIPS_E;
        static const int AESCCM_KAT_FIPS_E;
        static const int SHA3_KAT_FIPS_E;
        static const int ECDHE_KAT_FIPS_E;
        static const int AES_GCM_OVERFLOW_E;
        static const int AES_CCM_OVERFLOW_E;
        static const int RSA_KEY_PAIR_E;
        static const int DH_CHECK_PRIV_E;

        static const int WC_AFALG_SOCK_E;
        static const int WC_DEVCRYPTO_E;

        static const int ZLIB_INIT_ERROR;
        static const int ZLIB_COMPRESS_ERROR;
        static const int ZLIB_DECOMPRESS_ERROR;

        static const int PKCS7_NO_SIGNER_E;
        static const int WC_PKCS7_WANT_READ_E;

        static const int PKCS7_SIGNEEDS_CHECK;
        static const int PSS_SALTLEN_RECOVER_E;
        static const int CHACHA_POLY_OVERFLOW;
        static const int ASN_SELF_SIGNED_E;
        static const int SAKKE_VERIFY_FAIL_E;
        static const int MISSING_IV;
        static const int MISSING_KEY;
        static const int BAD_LENGTH_E;
        static const int ECDSA_KAT_FIPS_E;
        static const int RSA_PAT_FIPS_E;
        static const int KDF_TLS12_KAT_FIPS_E;
        static const int KDF_TLS13_KAT_FIPS_E;
        static const int KDF_SSH_KAT_FIPS_E;
        static const int DHE_PCT_E;
        static const int ECC_PCT_E;
        static const int FIPS_PRIVATE_KEY_LOCKED_E;
        static const int PROTOCOLCB_UNAVAILABLE;
        static const int AES_SIV_AUTH_E;
        static const int NO_VALID_DEVID;

        static const int IO_FAILED_E;
        static const int SYSLIB_FAILED_E;
        static const int USE_HW_PSK;

        static const int ENTROPY_RT_E;
        static const int ENTROPY_APT_E;

        static const int ASN_DEPTH_E;
        static const int ASN_LEN_E;

        static const int SM4_GCM_AUTH_E;
        static const int SM4_CCM_AUTH_E;

        static const int WC_SPAN1_LAST_E;
        static const int WC_SPAN1_MIN_CODE_E;

        static const int WC_SPAN2_FIRST_E;

        static const int DEADLOCK_AVERTED_E;
        static const int ASCON_AUTH_E;
        static const int WC_ACCEL_INHIBIT_E;
        static const int BAD_INDEX_E;
        static const int INTERRUPTED_E;

        static const int WC_SPAN2_LAST_E;
        static const int WC_LAST_E;

        static const int WC_SPAN2_MIN_CODE_E;
        static const int MIN_CODE_E;

        const char* wc_GetErrorString(int error);
        """

    if features["RNG"] and (not features["FIPS"] or features["FIPS_VERSION"] > 2):
        cdef += """
        int wc_GenerateSeed(OS_Seed* os, byte* seed, word32 sz);
        """

    if features["MPAPI"]:
        cdef += """
        typedef struct { ...; } mp_int;

        int mp_init (mp_int * a);
        void mp_clear (mp_int * a);
        int mp_to_unsigned_bin (mp_int * a, unsigned char *b);
        int mp_to_unsigned_bin_len (mp_int * a, unsigned char *b, int c);
        int mp_read_unsigned_bin (mp_int * a, const unsigned char *b, int c);
        """

    if features["SHA"]:
        cdef += """
        typedef struct { ...; } wc_Sha;
        int wc_InitSha_ex(wc_Sha*, void*, int);
        int wc_ShaUpdate(wc_Sha*, const byte*, word32);
        int wc_ShaFinal(wc_Sha*, byte*);
        void wc_ShaFree(wc_Sha*);
        int wc_ShaCopy(wc_Sha*, wc_Sha*);
        """

    if features["SHA256"]:
        cdef += """
        typedef struct { ...; } wc_Sha256;
        int wc_InitSha256_ex(wc_Sha256*, void*, int);
        int wc_Sha256Update(wc_Sha256*, const byte*, word32);
        int wc_Sha256Final(wc_Sha256*, byte*);
        void wc_Sha256Free(wc_Sha256*);
        int wc_Sha256Copy(wc_Sha256*, wc_Sha256*);
        """

    if features["SHA384"]:
        cdef += """
        typedef struct { ...; } wc_Sha384;
        int wc_InitSha384_ex(wc_Sha384*, void*, int);
        int wc_Sha384Update(wc_Sha384*, const byte*, word32);
        int wc_Sha384Final(wc_Sha384*, byte*);
        void wc_Sha384Free(wc_Sha384*);
        int wc_Sha384Copy(wc_Sha384*, wc_Sha384*);
        """

    if features["SHA512"]:
        cdef += """
        typedef struct { ...; } wc_Sha512;

        int wc_InitSha512_ex(wc_Sha512*, void*, int);
        int wc_Sha512Update(wc_Sha512*, const byte*, word32);
        int wc_Sha512Final(wc_Sha512*, byte*);
        void wc_Sha512Free(wc_Sha512*);
        int wc_Sha512Copy(wc_Sha512*, wc_Sha512*);
        """
    if features["SHA3"]:
        cdef += """
        typedef struct { ...; } wc_Sha3;
        """
        for bits in (224, 256, 384, 512):
            if features[f"SHA3_{bits}"]:
                cdef += f"""
                int wc_InitSha3_{bits}(wc_Sha3*, void *, int);
                int wc_Sha3_{bits}_Update(wc_Sha3*, const byte*, word32);
                int wc_Sha3_{bits}_Final(wc_Sha3*, byte*);
                void wc_Sha3_{bits}_Free(wc_Sha3*);
                int wc_Sha3_{bits}_Copy(wc_Sha3*, wc_Sha3*);
                """

    if features["DES3"]:
        cdef += """
            typedef struct { ...; } Des3;
            int wc_Des3_SetKey(Des3*, const byte*, const byte*, int);
            int wc_Des3_CbcEncrypt(Des3*, byte*, const byte*, word32);
            int wc_Des3_CbcDecrypt(Des3*, byte*, const byte*, word32);
        """

    if features["AES"]:
        cdef += """
        typedef struct { ...; } Aes;

        int wc_AesSetKey(Aes*, const byte*, word32, const byte*, int);
        """
        if features["AES_CBC"]:
            cdef += """
            int wc_AesCbcEncrypt(Aes*, byte*, const byte*, word32);
            """
        if features["AES_CBC"] and features["AES_DECRYPT"]:
            cdef += """
            int wc_AesCbcDecrypt(Aes*, byte*, const byte*, word32);
            """
        if features["AES_CTR"]:
            cdef += """
            int wc_AesCtrEncrypt(Aes*, byte*, const byte*, word32);
            """

    if features["AES"] and features["AESGCM_STREAM"]:
        cdef += """
        int  wc_AesInit(Aes* aes, void* heap, int devId);
        int wc_AesGcmInit(Aes* aes, const byte* key, word32 len,
            const byte* iv, word32 ivSz);
        int wc_AesGcmEncryptInit(Aes* aes, const byte* key, word32 len,
            const byte* iv, word32 ivSz);
        int wc_AesGcmEncryptInit_ex(Aes* aes, const byte* key, word32 len,
            byte* ivOut, word32 ivOutSz);
        int wc_AesGcmEncryptUpdate(Aes* aes, byte* out, const byte* in,
            word32 sz, const byte* authIn, word32 authInSz);
        int wc_AesGcmEncryptFinal(Aes* aes, byte* authTag,
            word32 authTagSz);
        void wc_AesFree(Aes* aes);
        """
        if features["AESGCM_STREAM_DECRYPT"]:
            cdef += """
            int wc_AesGcmDecryptInit(Aes* aes, const byte* key, word32 len,
                const byte* iv, word32 ivSz);
            int wc_AesGcmDecryptUpdate(Aes* aes, byte* out, const byte* in,
                word32 sz, const byte* authIn, word32 authInSz);
            int wc_AesGcmDecryptFinal(Aes* aes, const byte* authTag,
                word32 authTagSz);
            """

    if features["AES"] and features["AES_SIV"]:
        cdef += """
        typedef struct AesSivAssoc_s {
            const byte* assoc;
            word32 assocSz;
        } AesSivAssoc;
        int wc_AesSivEncrypt(const byte* key, word32 keySz, const byte* assoc,
                             word32 assocSz, const byte* nonce, word32 nonceSz,
                             const byte* in, word32 inSz, byte* siv, byte* out);
        int wc_AesSivDecrypt(const byte* key, word32 keySz, const byte* assoc,
                             word32 assocSz, const byte* nonce, word32 nonceSz,
                             const byte* in, word32 inSz, byte* siv, byte* out);
        int wc_AesSivEncrypt_ex(const byte* key, word32 keySz, const AesSivAssoc* assoc,
                                word32 numAssoc, const byte* nonce, word32 nonceSz,
                                const byte* in, word32 inSz, byte* siv, byte* out);
        int wc_AesSivDecrypt_ex(const byte* key, word32 keySz, const AesSivAssoc* assoc,
                                word32 numAssoc, const byte* nonce, word32 nonceSz,
                                const byte* in, word32 inSz, byte* siv, byte* out);
        """

    if features["CHACHA"]:
        cdef += """
        typedef struct { ...; } ChaCha;
        int wc_Chacha_SetKey(ChaCha*, const byte*, word32);
        int wc_Chacha_SetIV(ChaCha*, const byte*, word32);
        int wc_Chacha_Process(ChaCha*, byte*, const byte*,word32);
        """

    if features["CHACHA20_POLY1305"]:
        cdef += """
        typedef struct { ...; } ChaChaPoly_Aead;
        int wc_ChaCha20Poly1305_Encrypt(const byte* inKey, const byte* inIV, const byte* inAAD,
            word32 inAADLen, const byte* inPlaintext, word32 inPlaintextLen, byte* outCiphertext,
            byte* outAuthTag);
        int wc_ChaCha20Poly1305_Decrypt(const byte* inKey, const byte* inIV, const byte* inAAD,
            word32 inAADLen, const byte* inCiphertext, word32 inCiphertextLen,
            const byte* inAuthTag, byte* outPlaintext);
        int wc_ChaCha20Poly1305_UpdateAad(ChaChaPoly_Aead* aead,
            const byte* inAAD, word32 inAADLen);
        int wc_ChaCha20Poly1305_Init(ChaChaPoly_Aead* aead, const byte* inKey, const byte* inIV,
            int isEncrypt);
        int wc_ChaCha20Poly1305_UpdateData(ChaChaPoly_Aead* aead,
            const byte* inData, byte* outData, word32 dataLen);
        int wc_ChaCha20Poly1305_Final(ChaChaPoly_Aead* aead, byte* outTag);
        int wc_ChaCha20Poly1305_CheckTag(const byte* authtag, const byte* authTagChk);
        """

    if features["HMAC"]:
        cdef += """
        typedef struct { ...; } Hmac;
        int wc_HmacInit(Hmac* hmac, void* heap, int devId);
        int wc_HmacSetKey(Hmac*, int, const byte*, word32);
        int wc_HmacUpdate(Hmac*, const byte*, word32);
        int wc_HmacFinal(Hmac*, byte*);
        void wc_HmacFree(Hmac*);
        """
        if features["HMAC_COPY"]:
            cdef += """
            int wc_HmacCopy(Hmac* src, Hmac* dst);
            """

    cdef += """
        #define WC_MIN_DIGEST_SIZE ...
        #define WC_MAX_DIGEST_SIZE ...
        """

    if features["RSA"]:
        cdef += """
        static const int WC_RSA_PKCSV15_PAD;
        static const int WC_RSA_OAEP_PAD;
        static const int WC_RSA_PSS_PAD;
        static const int WC_RSA_NO_PAD;

        static const int WC_MGF1NONE;
        static const int WC_MGF1SHA1;
        static const int WC_MGF1SHA224;
        static const int WC_MGF1SHA256;
        static const int WC_MGF1SHA384;
        static const int WC_MGF1SHA512;

        static const int WC_HASH_TYPE_NONE;
        static const int WC_HASH_TYPE_MD2;
        static const int WC_HASH_TYPE_MD4;
        static const int WC_HASH_TYPE_MD5;
        static const int WC_HASH_TYPE_SHA;
        static const int WC_HASH_TYPE_SHA224;
        static const int WC_HASH_TYPE_SHA256;
        static const int WC_HASH_TYPE_SHA384;
        static const int WC_HASH_TYPE_SHA512;
        static const int WC_HASH_TYPE_MD5_SHA;
        static const int WC_HASH_TYPE_SHA3_224;
        static const int WC_HASH_TYPE_SHA3_256;
        static const int WC_HASH_TYPE_SHA3_384;
        static const int WC_HASH_TYPE_SHA3_512;
        static const int WC_HASH_TYPE_BLAKE2B;
        static const int WC_HASH_TYPE_BLAKE2S;
        typedef struct {...; } RsaKey;

        int wc_InitRsaKey(RsaKey* key, void*);
        int wc_FreeRsaKey(RsaKey* key);

        int wc_RsaEncryptSize(RsaKey*);
        """

        # asn.c has the RSA DER functions.
        if features["ASN"]:
            cdef += """
            int wc_RsaPrivateKeyDecode(const byte*, word32*, RsaKey*, word32);
            int wc_RsaPublicKeyDecode(const byte*, word32*, RsaKey*, word32);
            """

        if features["RSA_ENCRYPT"]:
            cdef += """
            int wc_RsaPublicEncrypt(const byte*, word32, byte*, word32,
                                    RsaKey*, WC_RNG*);
            """
            if features["RSA_OAEP"]:
                cdef += """
                int wc_RsaPublicEncrypt_ex(const byte* in, word32 inLen, byte* out,
                           word32 outLen, RsaKey* key, WC_RNG* rng, int type,
                           enum wc_HashType hash, int mgf, byte* label,
                           word32 labelSz);
                """

        if features["RSA_PRIVATE"]:
            cdef += """
            int wc_RsaPrivateDecrypt(const byte*, word32, byte*, word32,
                                    RsaKey* key);
            """
            if features["RSA_OAEP"]:
                cdef += """
                int wc_RsaPrivateDecrypt_ex(const byte* in, word32 inLen,
                           byte* out, word32 outLen, RsaKey* key, int type,
                           enum wc_HashType hash, int mgf, byte* label,
                           word32 labelSz);
                """

        if features["RSA_SIGN"]:
            cdef += """
            int wc_RsaSSL_Sign(const byte*, word32, byte*, word32, RsaKey*, WC_RNG*);
            """

        if features["RSA_VERIFY"]:
            cdef += """
            int wc_RsaSSL_Verify(const byte*, word32, byte*, word32, RsaKey*);
            """

        if features["RSA_PSS"] and features["RSA_SIGN"]:
            cdef += """
            int wc_RsaPSS_Sign(const byte* in, word32 inLen, byte* out, word32 outLen,
                               enum wc_HashType hash, int mgf, RsaKey* key, WC_RNG* rng);
            """

        if features["RSA_PSS"]:
            cdef += """
            int wc_RsaPSS_Verify(const byte* in, word32 inLen, byte* out, word32 outLen,
                                   enum wc_HashType hash, int mgf, RsaKey* key);
            int wc_RsaPSS_CheckPadding(const byte* in, word32 inSz, byte* sig,
                                   word32 sigSz, enum wc_HashType hashType);
            """

        if features["RSA_BLINDING"]:
            cdef += """
            int wc_RsaSetRNG(RsaKey* key, WC_RNG* rng);
            """

        if features["KEYGEN"] and features["RSA_PRIVATE"]:
            cdef += """
            int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng);
            """

        if features["KEYGEN"] and features["ASN"]:
            cdef += """
            int wc_RsaKeyToDer(RsaKey* key, byte* output, word32 inLen);
            """

        # asn.c builds wc_RsaKeyToPublicDer only with certificate support.
        if features["KEYGEN"] and features["CERTS"]:
            cdef += """
            int wc_RsaKeyToPublicDer(RsaKey* key, byte* output, word32 inLen);

            """

    if features["ECC"]:
        cdef += """
        typedef struct { int type; ...; } ecc_key;
        static const int ECC_PRIVATEKEY;

        int wc_ecc_init(ecc_key* ecc);
        void wc_ecc_free(ecc_key* ecc);

        int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key);
        int wc_ecc_size(ecc_key* key);
        int wc_ecc_sig_size(ecc_key* key);
        int wc_ecc_get_curve_size_from_id(int curve_id);
        int wc_ecc_check_key(ecc_key* key);
        """

        if features["ECC_KEY_IMPORT"] and features["ASN"]:
            cdef += """
            int wc_EccPrivateKeyDecode(const byte*, word32*, ecc_key*, word32);
            int wc_EccPublicKeyDecode(const byte*, word32*, ecc_key*, word32);
            """

        if features["ECC_KEY_IMPORT"]:
            cdef += """
            int wc_ecc_import_x963(const byte* in, word32 inLen, ecc_key* key);
            int wc_ecc_import_unsigned(ecc_key* key, const byte* qx, const byte* qy,
                           const byte* d, int curve_id);
            """

        if features["ECC_KEY_EXPORT"] and features["ASN"]:
            cdef += """
            int wc_EccKeyToDer(ecc_key*, byte* output, word32 inLen);
            int wc_EccKeyDerSize(ecc_key*, int pub);
            int wc_EccPublicKeyToDer(ecc_key*, byte* output,
                                     word32 inLen, int with_AlgCurve);
            """

        if features["ECC_KEY_EXPORT"]:
            cdef += """
            int wc_ecc_export_x963(ecc_key*, byte* out, word32* outLen);
            int wc_ecc_export_private_raw(ecc_key* key, byte* qx, word32* qxLen,
                                      byte* qy, word32* qyLen, byte* d, word32* dLen);
            int wc_ecc_export_public_raw(ecc_key* key, byte* qx, word32* qxLen,
                                     byte* qy, word32* qyLen);
            """

        if features["ECC_DHE"]:
            cdef += """
            int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
                                     byte* out, word32* outlen);
            """

        if features["ECC_SIGN"]:
            cdef += """
            int wc_ecc_sign_hash(const byte* in, word32 inlen,
                                 byte* out, word32 *outlen,
                                 WC_RNG* rng, ecc_key* key);
            """
            if features["MPAPI"]:
                cdef += """
                int wc_ecc_sign_hash_ex(const byte* in, word32 inlen, WC_RNG* rng,
                                     ecc_key* key, mp_int *r, mp_int *s);
                """

        if features["ECC_VERIFY"]:
            cdef += """
            int wc_ecc_verify_hash(const byte* sig, word32 siglen,
                                   const byte* hash, word32 hashlen,
                                   int* stat, ecc_key* key);
            """
            if features["MPAPI"]:
                cdef += """
                int wc_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                                word32 hashlen, int* res, ecc_key* key);
                """

        if features["ECC_TIMING_RESISTANCE"] and (not features["FIPS"] or
           features["FIPS_VERSION"] > 2):
            cdef += """
            int wc_ecc_set_rng(ecc_key* key, WC_RNG* rng);
            """


    if features["ED25519"]:
        cdef += """
        typedef struct {...; } ed25519_key;

        int wc_ed25519_init(ed25519_key* ed25519);
        void wc_ed25519_free(ed25519_key* ed25519);

        int wc_ed25519_size(ed25519_key* key);
        int wc_ed25519_sig_size(ed25519_key* key);
        int wc_ed25519_check_key(ed25519_key* key);
        int wc_ed25519_pub_size(ed25519_key* key);
        int wc_ed25519_priv_size(ed25519_key* key);
        """

        if features["ED25519_MAKE_KEY"]:
            cdef += """
            int wc_ed25519_make_key(WC_RNG* rng, int keysize, ed25519_key* key);
            int wc_ed25519_make_public(ed25519_key* key, unsigned char* pubKey,
                                   word32 pubKeySz);
            """

        if features["ED25519_SIGN"]:
            cdef += """
            int wc_ed25519_sign_msg(const byte* in, word32 inlen, byte* out,
                                word32 *outlen, ed25519_key* key);
            """

        if features["ED25519_VERIFY"]:
            cdef += """
            int wc_ed25519_verify_msg(const byte* sig, word32 siglen, const byte* msg,
                                  word32 msglen, int* stat, ed25519_key* key);
            """

        if features["ED25519_KEY_IMPORT"] and features["ASN"]:
            cdef += """
            int wc_Ed25519PrivateKeyDecode(const byte*, word32*, ed25519_key*, word32);
            int wc_Ed25519PublicKeyDecode(const byte*, word32*, ed25519_key*, word32);
            """

        if features["ED25519_KEY_IMPORT"]:
            cdef += """
            int wc_ed25519_import_public(const byte* in, word32 inLen, ed25519_key* key);
            int wc_ed25519_import_private_only(const byte* priv, word32 privSz, ed25519_key* key);
            int wc_ed25519_import_private_key(const byte* priv, word32 privSz, const byte* pub, word32 pubSz, ed25519_key* key);
            """

        if features["ED25519_KEY_EXPORT"] and features["ASN"]:
            cdef += """
            int wc_Ed25519KeyToDer(ed25519_key*, byte* output, word32 inLen);
            int wc_Ed25519PublicKeyToDer(ed25519_key*, byte* output,
                                     word32 inLen, int with_AlgCurve);
            """

        if features["ED25519_KEY_EXPORT"]:
            cdef += """
            int wc_ed25519_export_public(ed25519_key*, byte* out, word32* outLen);
            int wc_ed25519_export_private_only(ed25519_key* key, byte* out, word32* outLen);
            int wc_ed25519_export_private(ed25519_key* key, byte* out, word32* outLen);
            int wc_ed25519_export_key(ed25519_key* key, byte* priv, word32 *privSz, byte* pub, word32 *pubSz);
            """

    if features["ED448"]:
        cdef += """
        typedef struct {...; } ed448_key;

        int wc_ed448_init(ed448_key* ed448);
        void wc_ed448_free(ed448_key* ed448);

        int wc_ed448_make_key(WC_RNG* rng, int keysize, ed448_key* key);
        int wc_ed448_make_public(ed448_key* key, unsigned char* pubKey,
                               word32 pubKeySz);
        int wc_ed448_size(ed448_key* key);
        int wc_ed448_sig_size(ed448_key* key);
        int wc_ed448_check_key(ed448_key* key);
        int wc_ed448_pub_size(ed448_key* key);
        int wc_ed448_priv_size(ed448_key* key);
        """

        if features["ED448_SIGN"]:
            cdef += """
            int wc_ed448_sign_msg(const byte* in, word32 inlen, byte* out,
                                word32 *outlen, ed448_key* key, const byte* ctx,
                                byte ctx_len);
            """

        if features["ED448_VERIFY"]:
            cdef += """
            int wc_ed448_verify_msg(const byte* sig, word32 siglen, const byte* msg,
                                  word32 msglen, int* stat, ed448_key* key, const byte *ctx,
                                  byte ctx_len);
            """

        if features["ED448_KEY_IMPORT"] and features["ASN"]:
            cdef += """
            int wc_Ed448PrivateKeyDecode(const byte*, word32*, ed448_key*, word32);
            int wc_Ed448PublicKeyDecode(const byte*, word32*, ed448_key*, word32);
            """

        if features["ED448_KEY_IMPORT"]:
            cdef += """
            int wc_ed448_import_public(const byte* in, word32 inLen, ed448_key* key);
            int wc_ed448_import_private_only(const byte* priv, word32 privSz, ed448_key* key);
            int wc_ed448_import_private_key(const byte* priv, word32 privSz, const byte* pub, word32 pubSz, ed448_key* key);
            """

        if features["ED448_KEY_EXPORT"] and features["ASN"]:
            cdef += """
            int wc_Ed448KeyToDer(ed448_key*, byte* output, word32 inLen);
            int wc_Ed448PublicKeyToDer(ed448_key*, byte* output,
                                     word32 inLen, int with_AlgCurve);
            """

        if features["ED448_KEY_EXPORT"]:
            cdef += """
            int wc_ed448_export_public(ed448_key*, byte* out, word32* outLen);
            int wc_ed448_export_private_only(ed448_key* key, byte* out, word32* outLen);
            int wc_ed448_export_private(ed448_key* key, byte* out, word32* outLen);
            int wc_ed448_export_key(ed448_key* key, byte* priv, word32 *privSz, byte* pub, word32 *pubSz);
            """

    if features["HKDF"]:
        cdef += """
        int wc_HKDF(int type, const byte* inKey, word32 inKeySz,
                    const byte* salt, word32 saltSz,
                    const byte* info, word32 infoSz,
                    byte* out, word32 outSz);
        int wc_HKDF_Extract(int type, const byte* salt, word32 saltSz,
                            const byte* inKey, word32 inKeySz, byte* out);
        int wc_HKDF_Extract_ex(int type, const byte* salt, word32 saltSz,
                               const byte* inKey, word32 inKeySz, byte* out,
                               void* heap, int devId);
        int wc_HKDF_Expand(int type, const byte* inKey, word32 inKeySz,
                           const byte* info, word32 infoSz,
                           byte* out, word32 outSz);
        int wc_HKDF_Expand_ex(int type, const byte* inKey, word32 inKeySz,
                              const byte* info, word32 infoSz,
                              byte* out, word32 outSz,
                              void* heap, int devId);
        """

    if features["PBKDF2"]:
        cdef += """
        int wc_PBKDF2(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int typeH);
        """

    if features["ASN"]:
        cdef += """
        static const long PRIVATEKEY_TYPE;
        static const long PUBLICKEY_TYPE;
        static const long CERT_TYPE;
        static const long MAX_DER_DIGEST_SZ;
        static const long SHAh;
        static const long SHA256h;
        static const long SHA384h;
        static const long SHA512h;

        word32 wc_EncodeSignature(byte* out, const byte* digest, word32 digSz,
                                  int hashOID);
        """

    if features["PEM_TO_DER"]:
        cdef += """
        typedef struct DerBuffer {
            byte*  buffer;
            void*  heap;
            word32 length;
            int    type;
            int    dynType;
        } DerBuffer;
        typedef struct { ...; } EncryptedInfo;

        int wc_PemToDer(const unsigned char* buff, long longSz, int type,
                        DerBuffer** pDer, void* heap, EncryptedInfo* info,
                        int* keyFormat);
        void wc_FreeDer(DerBuffer** pDer);
        """

    if features["DER_TO_PEM"]:
        cdef += """
        int wc_DerToPemEx(const byte* der, word32 derSz, byte* output, word32 outSz,
                        byte *cipher_info, int type);
        """

    if features["PKCS8"]:
        cdef += """
        int wc_GetPkcs8TraditionalOffset(byte* input, word32* inOutIdx, word32 sz);
        """

    if features["WC_RNG_SEED_CB"]:
        cdef += """
        typedef int (*wc_RngSeed_Cb)(OS_Seed* os, byte* seed, word32 sz);

        int wc_SetSeed_Cb(wc_RngSeed_Cb cb);
        """

    if features["FIPS"] and features["FIPS_VERSION"] >= 5:
        cdef += """
        enum wc_KeyType {
            WC_KEYTYPE_ALL = 0
        };

        int wolfCrypt_SetPrivateKeyReadEnable_fips(int, enum wc_KeyType);
        int wolfCrypt_GetPrivateKeyReadEnable_fips(enum wc_KeyType);
        """

    if features["ML_KEM"]:
        cdef += """
        static const int WC_ML_KEM_512;
        static const int WC_ML_KEM_768;
        static const int WC_ML_KEM_1024;
        typedef struct {...; } KyberKey;
        int wc_KyberKey_CipherTextSize(KyberKey* key, word32* len);
        int wc_KyberKey_SharedSecretSize(KyberKey* key, word32* len);
        int wc_KyberKey_PrivateKeySize(KyberKey* key, word32* len);
        int wc_KyberKey_PublicKeySize(KyberKey* key, word32* len);
        int wc_KyberKey_Init(int type, KyberKey* key, void* heap, int devId);
        void wc_KyberKey_Free(KyberKey* key);
        int wc_KyberKey_EncodePublicKey(KyberKey* key, unsigned char* out, word32 len);
        int wc_KyberKey_DecodePublicKey(KyberKey* key, const unsigned char* in, word32 len);
        int wc_KyberKey_EncodePrivateKey(KyberKey* key, unsigned char* out, word32 len);
        int wc_KyberKey_DecodePrivateKey(KyberKey* key, const unsigned char* in, word32 len);
        """

        if features["ML_KEM_MAKE_KEY"]:
            cdef += """
            int wc_KyberKey_MakeKey(KyberKey* key, WC_RNG* rng);
            int wc_KyberKey_MakeKeyWithRandom(KyberKey* key, const unsigned char* rand, int len);
            """

        if features["ML_KEM_ENCAPSULATE"]:
            cdef += """
            int wc_KyberKey_Encapsulate(KyberKey* key, unsigned char* ct, unsigned char* ss, WC_RNG* rng);
            int wc_KyberKey_EncapsulateWithRandom(KyberKey* key, unsigned char* ct, unsigned char* ss, const unsigned char* rand, int len);
            """

        if features["ML_KEM_DECAPSULATE"]:
            cdef += """
            int wc_KyberKey_Decapsulate(KyberKey* key, unsigned char* ss, const unsigned char* ct, word32 len);
            """

    if features["ML_DSA"]:
        cdef += """
        static const int DILITHIUM_SEED_SZ;
        static const int WC_ML_DSA_44;
        static const int WC_ML_DSA_65;
        static const int WC_ML_DSA_87;
        typedef struct {...; } dilithium_key;
        int wc_dilithium_init_ex(dilithium_key* key, void* heap, int devId);
        int wc_dilithium_set_level(dilithium_key* key, byte level);
        void wc_dilithium_free(dilithium_key* key);
        typedef dilithium_key MlDsaKey;
        """

        if features["ML_DSA_MAKE_KEY"]:
            cdef += """
            int wc_dilithium_make_key(dilithium_key* key, WC_RNG* rng);
            int wc_dilithium_make_key_from_seed(dilithium_key* key, const byte* seed);
            """

        if features["ML_DSA_PRIVATE_KEY"]:
            cdef += """
            int wc_dilithium_export_private(dilithium_key* key, byte* out, word32* outLen);
            int wc_dilithium_import_private(const byte* priv, word32 privSz, dilithium_key* key);
            """

        if features["ML_DSA_PUBLIC_KEY"]:
            cdef += """
            int wc_dilithium_export_public(dilithium_key* key, byte* out, word32* outLen);
            int wc_dilithium_import_public(const byte* in, word32 inLen, dilithium_key* key);
            int wc_MlDsaKey_GetPubLen(MlDsaKey* key, int* len);
            """

        if features["ML_DSA_PRIVATE_KEY"] and features["ML_DSA_PUBLIC_KEY"]:
            cdef += """
            int wc_MlDsaKey_GetPrivLen(MlDsaKey* key, int* len);
            """

        if features["ML_DSA_SIGN"] or features["ML_DSA_VERIFY"]:
            cdef += """
            int wc_MlDsaKey_GetSigLen(MlDsaKey* key, int* len);
            """

        if features["ML_DSA_SIGN"]:
            cdef += """
            int wc_dilithium_sign_ctx_msg(const byte* ctx, byte ctxLen, const byte* msg, word32 msgLen, byte* sig, word32* sigLen, dilithium_key* key, WC_RNG* rng);
            int wc_dilithium_sign_ctx_msg_with_seed(const byte* ctx, byte ctxLen, const byte* msg, word32 msgLen, byte* sig, word32* sigLen, dilithium_key* key, const byte* seed);
            """
            if features["ML_DSA_NO_CTX"]:
                cdef += """
                int wc_dilithium_sign_msg(const byte* msg, word32 msgLen, byte* sig, word32* sigLen, dilithium_key* key, WC_RNG* rng);
                int wc_dilithium_sign_msg_with_seed(const byte* msg, word32 msgLen, byte* sig, word32* sigLen, dilithium_key* key, const byte* seed);
                """

        if features["ML_DSA_VERIFY"]:
            cdef += """
            int wc_dilithium_verify_ctx_msg(const byte* sig, word32 sigLen, const byte* ctx, byte ctxLen, const byte* msg, word32 msgLen, int* res, dilithium_key* key);
            """
            if features["ML_DSA_NO_CTX"]:
                cdef += """
                int wc_dilithium_verify_msg(const byte* sig, word32 sigLen, const byte* msg, word32 msgLen, int* res, dilithium_key* key);
                """

    if features["CRYPTO_CB"]:
        cdef += """
        static const int WC_ALGO_TYPE_NONE;
        static const int WC_ALGO_TYPE_HASH;
        static const int WC_ALGO_TYPE_CIPHER;
        static const int WC_ALGO_TYPE_PK;
        static const int WC_ALGO_TYPE_RNG;
        static const int WC_ALGO_TYPE_SEED;
        static const int WC_ALGO_TYPE_HMAC;
        static const int WC_ALGO_TYPE_CMAC;
        static const int WC_ALGO_TYPE_CERT;
        static const int WC_ALGO_TYPE_KDF;
        static const int WC_ALGO_TYPE_COPY;
        static const int WC_ALGO_TYPE_FREE;
        static const int WC_ALGO_TYPE_MAX;

        static const int WC_HASH_TYPE_SHA; /* SHA-1 (not old SHA-0) */
        static const int WC_HASH_TYPE_SHA256;
        static const int WC_HASH_TYPE_SHA384;
        static const int WC_HASH_TYPE_SHA512;
        static const int WC_HASH_TYPE_SHA3_256;
        static const int WC_HASH_TYPE_SHA3_384;
        static const int WC_HASH_TYPE_SHA3_512;
        """


        cdef += """
        typedef struct {
            int algo_type; /* enum wc_AlgoType */
            union {
        """

        # The following block is commented out as there are issues with cffi code generation for the
        # wc_CryptoInfo structure with two layers of anonymous unions.
        # Uncommenting more parts of the cipher struct causes errors regarding conflicting struct sizes of
        # other parts of the wc_CryptoInfo struct.
        # Cffi cdef and the compiler seem to disagree.
        #
        # cdef += """
        #     struct {
        #         int type; /* enum wc_CipherType */
        #         int enc;
        #         union {
        #             //wc_CryptoCb_AesAuthEnc aesgcm_enc;
        #             //wc_CryptoCb_AesAuthDec aesgcm_dec;
        #             //wc_CryptoCb_AesAuthEnc aesccm_enc;
        #             //wc_CryptoCb_AesAuthDec aesccm_dec;
        #             struct {
        #                 Aes*        aes;
        #                 byte*       out;
        #                 const byte* in;
        #                 word32      sz;
        #             } aescbc;
        #             //struct {
        #             //    Aes*        aes;
        #             //    byte*       out;
        #             //    const byte* in;
        #             //    word32      sz;
        #             //} aesctr;
        #             //struct {
        #             //    Aes*        aes;
        #             //    byte*       out;
        #             //    const byte* in;
        #             //    word32      sz;
        #             //} aesecb;
        #             //struct {
        #             //    Des3*       des;
        #             //    byte*       out;
        #             //    const byte* in;
        #             //    word32      sz;
        #             //} des3;
        #             //void* ctx;
        #         };
        #     } cipher;
        # """

        # wolfSSL names the input fields in/inSz; renamed here because "in" is a
        # Python keyword. The layout must still match wc_CryptoInfo in cryptocb.h.
        cdef += """
            struct {
                int type; /* enum wc_HashType */
                const byte* data;
                word32 data_size;
                byte* digest;
                union {
        """
        if features["SHA"]:
            cdef += """
                    wc_Sha* sha1;
            """
        if features["SHA256"]:
            cdef += """
                    wc_Sha256* sha256;
            """
        if features["SHA384"]:
            cdef += """
                    wc_Sha384* sha384;
            """
        if features["SHA512"]:
            cdef += """
                    wc_Sha512* sha512;
            """
        if features["SHA3"]:
            cdef += """
                    wc_Sha3* sha3;
            """
        cdef += """
                    void* ctx;
                } u;
            } hash;
        """
        if features["RNG"]:
            cdef += """
            struct {
                WC_RNG* rng;
                byte* out;
                word32 sz;
            } rng;
            """
        if features["CRYPTO_CB_COPY"]:
            cdef += """
            struct {
                int algo; /* enum wc_AlgoType */
                int type; /* enum wc_HashType for WC_ALGO_TYPE_HASH */
                void* src;
                void* dst;
            } copy;
            """
        if features["CRYPTO_CB_FREE"]:
            cdef += """
            struct {
                int algo; /* enum wc_AlgoType */
                int type; /* enum wc_HashType for WC_ALGO_TYPE_HASH */
                int subType;
                void* obj;
            } free;
            """
        cdef += """
            };
            ...;
        } wc_CryptoInfo;

        typedef int (*CryptoDevCallbackFunc)(int devId, wc_CryptoInfo* info, void* ctx);
        extern "Python" int py_wc_crypto_callback(int devId, wc_CryptoInfo* info, void* ctx);
        int wc_CryptoCb_RegisterDevice(int devId, CryptoDevCallbackFunc cb, void* ctx);
        void wc_CryptoCb_UnRegisterDevice(int devId);
        int wc_CryptoCb_DefaultDevID();
        // void wc_CryptoCb_InfoString(wc_CryptoInfo* info);
        """

    return cdef

def default_features():
    """Return the default features, before detection."""
    features = {
        "MPAPI": 1,
        "SHA": 1,
        "SHA256": 1,
        "SHA384": 1,
        "SHA512": 1,
        "SHA3": 1,
        "DES3": 1,
        "AES": 1,
        "AES_SIV": 1,
        "HMAC": 1,
        "RSA": 1,
        "RSA_BLINDING": 1,
        "ECC_TIMING_RESISTANCE": 1,
        "ECC": 1,
        "ED25519": 1,
        "KEYGEN": 1,
        "CHACHA": 1,
        "PWDBASED": 1,
        "FIPS": 0,
        "FIPS_VERSION": 0,
        "ERROR_STRINGS": 1,
        "ASN": 1,
        "CERTS": 1,
        "WC_RNG_SEED_CB": 0,
        "AESGCM_STREAM": 1,
        "MIN_AUTH_TAG_SZ": 12,
        "RSA_PSS": 1,
        "CHACHA20_POLY1305": 1,
        "ML_KEM": 1,
        "ML_DSA": 1,
        "ML_DSA_NO_CTX": 0,
        "HKDF": 1,
        "HASHDRBG": 1,
        "CRYPTO_CB": 1,
        "CRYPTO_CB_COPY": 1,
        "CRYPTO_CB_FREE": 1,
        "HMAC_COPY": 1,
        "AES_CTR": 1,
        "AES_CBC": 1,
        "AES_DECRYPT": 1,
        "AESGCM_STREAM_DECRYPT": 1,
        "SHA3_224": 1,
        "SHA3_256": 1,
        "SHA3_384": 1,
        "SHA3_512": 1,
        "PBKDF2": 1,
        "PEM_TO_DER": 1,
        "DER_TO_PEM": 1,
        "PKCS8": 1,
        "RNG": 1,
        "RSA_ENCRYPT": 1,
        "RSA_PRIVATE": 1,
        "RSA_SIGN": 1,
        "RSA_VERIFY": 1,
        "RSA_OAEP": 1,
        "ECC_SIGN": 1,
        "ECC_VERIFY": 1,
        "ECC_DHE": 1,
        "ECC_KEY_IMPORT": 1,
        "ECC_KEY_EXPORT": 1,
        "ED25519_MAKE_KEY": 1,
        "ED25519_SIGN": 1,
        "ED25519_VERIFY": 1,
        "ED25519_KEY_IMPORT": 1,
        "ED25519_KEY_EXPORT": 1,
        "ED448_SIGN": 1,
        "ED448_VERIFY": 1,
        "ED448_KEY_IMPORT": 1,
        "ED448_KEY_EXPORT": 1,
        "ML_KEM_MAKE_KEY": 1,
        "ML_KEM_ENCAPSULATE": 1,
        "ML_KEM_DECAPSULATE": 1,
        "ML_DSA_MAKE_KEY": 1,
        "ML_DSA_SIGN": 1,
        "ML_DSA_VERIFY": 1,
        "ML_DSA_PUBLIC_KEY": 1,
        "ML_DSA_PRIVATE_KEY": 1,
    }

    # Ed448 requires SHAKE256, which isn't part of the Windows build, yet.
    if sys.platform == "win32":
        features["ED448"] = 0
    else:
        features["ED448"] = 1

    return features

def main(ffibuilder):
    features = default_features()

    local_wolfssl = os.environ.get("USE_LOCAL_WOLFSSL")
    if local_wolfssl:
        print(f"Using local wolfSSL at {local_wolfssl}.")
        if not os.path.exists(local_wolfssl):
            e = f"Local wolfssl installation path {local_wolfssl} doesn't exist."
            raise FileNotFoundError(e)

    if not local_wolfssl:
        print("Building wolfSSL...")
        if not get_libwolfssl():
            generate_libwolfssl(features["FIPS"])

    get_features(local_wolfssl, features)

    if features["RSA_BLINDING"] and features["FIPS"]:
        # These settings can't coexist. See settings.h.
        features["RSA_BLINDING"] = 0

    build_ffi(local_wolfssl, features)


ffibuilder = FFI()

# cffi's setuptools integration runs this file with __name__ == "__cffi__".
if __name__ in ("__main__", "__cffi__"):
    main(ffibuilder)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
