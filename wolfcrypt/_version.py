# When bumping the C library version, reset the POST count to 0

__wolfssl_version__ = "v5.5.4-stable"

# We're using implicit post releases [PEP 440] to bump package version
# while maintaining the C library version intact for better reference.
# https://www.python.org/dev/peps/pep-0440/#implicit-post-releases
#
# MAJOR.MINOR.BUILD-POST

__version__ = "5.5.4-0"

