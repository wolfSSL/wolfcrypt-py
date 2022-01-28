Streaming Encryption Algorithms
===============================

.. module:: wolfcrypt.ciphers

Steaming Encryption Classes
---------------------------

Interface
~~~~~~~~~

AesGcmStreamEncrypt
~~~~~~~~~~~~~~~~~~~

.. autoclass:: AesGcmStreamEncrypt
    :members:
    :inherited-members:

**Example:**

.. doctest::

    >>> from wolfcrypt.ciphers import AesGcmStreamEncrypt
    >>> from binascii import hexlify as b2h
    >>> gcm = AesGcmStreamEncrypt(b'fedcba9876543210', b'0123456789abcdef')
    >>> buf = gcm.update("hello world")
    >>> authTag = gcm.final()
    >>> b2h(buf)
    b'5ba7d42e1bf01d7998e932'
    >>> b2h(authTag)
    b'cef91ba0c8c6431c7e19f64c9d9e371b'

AesGcmStreamDecrypt
~~~~~~~~~~~~~~~~~~~

.. autoclass:: AesGcmStreamDecrypt
    :members:
    :inherited-members:

**Example:**

.. doctest::

    >>> from wolfcrypt.ciphers import AesGcmStreamDecrypt, t2b
    >>> from binascii import unhexlify as h2b
    >>> gcm = AesGcmStreamDecrypt(b'fedcba9876543210', b'0123456789abcdef')
    >>> buf = gcm.update(h2b(b'5ba7d42e1bf01d7998e932'))
    >>> gcm.final(h2b(b'cef91ba0c8c6431c7e19f64c9d9e371b'))
    >>> t2b(buf)
    b'hello world'
