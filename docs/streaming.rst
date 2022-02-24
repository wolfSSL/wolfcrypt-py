Streaming Encryption Algorithms
===============================

.. module:: wolfcrypt.ciphers

Steaming Encryption Classes
---------------------------

Interface
~~~~~~~~~

AesGcmStream
~~~~~~~~~~~~

.. autoclass:: AesGcmStream
    :members:
    :inherited-members:

**Example:**

.. doctest::

    >>> from wolfcrypt.ciphers import AesGcmStreamEncrypt
    >>> from binascii import hexlify as b2h
    >>> gcm = AesGcmStream(b'fedcba9876543210', b'0123456789abcdef')
    >>> buf = gcm.encrypt("hello world")
    >>> authTag = gcm.final()
    >>> b2h(buf)
    b'5ba7d42e1bf01d7998e932'
    >>> b2h(authTag)
    b'8f85338aa0b13f48f8b17482dbb8acca'
    >>> gcm = AesGcmStream(b'fedcba9876543210', b'0123456789abcdef')
    >>> buf = gcm.decrypt(h2b(b'5ba7d42e1bf01d7998e932'))
    >>> gcm.final(h2b(b'8f85338aa0b13f48f8b17482dbb8acca'))
    >>> t2b(buf)
    b'hello world'
