"""Cryptographic primitives of EBICS 3.0: A006, X002, E002, digests and certificates."""

from __future__ import annotations

import hashlib
import os
import secrets
import zlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

__all__ = [
    "AUTHENTICATION",
    "ENCRYPTION",
    "MAX_KEY_SIZE",
    "MIN_KEY_SIZE",
    "SIGNATURE",
    "a006_sign",
    "a006_verify",
    "aes_decrypt",
    "aes_encrypt",
    "certificate_digest",
    "certificate_from_bytes",
    "check_key_size",
    "compress",
    "decompress",
    "e002_decrypt",
    "e002_encrypt",
    "ebics_pad",
    "ebics_unpad",
    "generate_certificate",
    "generate_private_key",
    "generate_transaction_key",
    "normalize_order_data",
    "x002_sign",
    "x002_verify",
]

SIGNATURE = "A006"
AUTHENTICATION = "X002"
ENCRYPTION = "E002"

MIN_KEY_SIZE = 2048
MAX_KEY_SIZE = 4096

#: Validity end of generated certificates. The Swiss market practice guidelines name
#: 9999-12-31 as "unlimited"; an expired certificate means initialising again.
UNLIMITED = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

_BLOCK = 16
_ZERO_IV = b"\x00" * _BLOCK
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def generate_private_key(key_size: int = MIN_KEY_SIZE) -> rsa.RSAPrivateKey:
    """Generate an RSA key of key_size bits (2048 to 4096) with exponent 65537."""
    if not MIN_KEY_SIZE <= key_size <= MAX_KEY_SIZE:
        raise ValueError(
            f"EBICS keys must be {MIN_KEY_SIZE} to {MAX_KEY_SIZE} bits, got {key_size}"
        )
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def check_key_size(public_key: rsa.RSAPublicKey, minimum: int = MIN_KEY_SIZE) -> None:
    """Raise ValueError when the key is smaller than minimum or larger than 4096 bits."""
    if not minimum <= public_key.key_size <= MAX_KEY_SIZE:
        raise ValueError(
            f"RSA key of {public_key.key_size} bits outside {minimum} to {MAX_KEY_SIZE}"
        )


def normalize_order_data(data: bytes) -> bytes:
    """Remove CR, LF and Ctrl-Z, as EBICS does before hashing order data for A006."""
    return data.replace(b"\r", b"").replace(b"\n", b"").replace(b"\x1a", b"")


def a006_sign(private_key: rsa.RSAPrivateKey, order_data: bytes) -> bytes:
    """Sign order data with A006 (RSASSA-PSS, SHA-256, MGF1 SHA-256, salt length 32).

    The PSS input is the SHA-256 hash of the order data (the EBICS "hash value of the
    order data"), which PSS hashes once more. railslove/epics and node-ebics-client
    sign the same way.
    """
    digest = hashlib.sha256(order_data).digest()
    return private_key.sign(digest, _PSS, hashes.SHA256())


def a006_verify(public_key: rsa.RSAPublicKey, signature: bytes, order_data: bytes) -> bool:
    """Return True when signature is a valid A006 signature of order_data."""
    digest = hashlib.sha256(order_data).digest()
    try:
        public_key.verify(signature, digest, _PSS, hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def x002_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Sign data with X002 (RSASSA-PKCS1-v1_5 with SHA-256)."""
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def x002_verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """Return True when signature is a valid X002 signature of data."""
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def ebics_pad(data: bytes) -> bytes:
    """Pad to the next full AES block: zero bytes, last byte is the pad length (1 to 16)."""
    pad_len = _BLOCK - (len(data) % _BLOCK)
    return data + b"\x00" * (pad_len - 1) + bytes([pad_len])


def ebics_unpad(data: bytes) -> bytes:
    """Remove EBICS padding, raising ValueError when it is malformed."""
    if not data or len(data) % _BLOCK:
        raise ValueError("padded data must be a non-empty multiple of 16 bytes")
    pad_len = data[-1]
    if not 1 <= pad_len <= _BLOCK:
        raise ValueError("invalid EBICS padding")
    return data[:-pad_len]


def generate_transaction_key() -> bytes:
    """Return a fresh random 16 byte AES-128 transaction key."""
    return secrets.token_bytes(16)


def aes_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-CBC with a zero IV over the EBICS-padded data."""
    encryptor = Cipher(algorithms.AES(key), modes.CBC(_ZERO_IV)).encryptor()
    return encryptor.update(ebics_pad(data)) + encryptor.finalize()


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """Reverse aes_encrypt; raises ValueError on a bad length or padding."""
    if not data or len(data) % _BLOCK:
        raise ValueError("ciphertext must be a non-empty multiple of 16 bytes")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(_ZERO_IV)).decryptor()
    return ebics_unpad(decryptor.update(data) + decryptor.finalize())


def e002_encrypt(
    public_key: rsa.RSAPublicKey, data: bytes, transaction_key: bytes | None = None
) -> tuple[bytes, bytes]:
    """Encrypt data for public_key with E002.

    Returns (encrypted transaction key, ciphertext). The transaction key is wrapped
    with RSAES-PKCS1-v1_5; data is AES-128-CBC encrypted with it.
    """
    key = transaction_key if transaction_key is not None else generate_transaction_key()
    return public_key.encrypt(key, padding.PKCS1v15()), aes_encrypt(key, data)


def e002_decrypt(private_key: rsa.RSAPrivateKey, encrypted_key: bytes, ciphertext: bytes) -> bytes:
    """Unwrap the transaction key with private_key and decrypt ciphertext."""
    return aes_decrypt(decrypt_transaction_key(private_key, encrypted_key), ciphertext)


def encrypt_transaction_key(public_key: rsa.RSAPublicKey, transaction_key: bytes) -> bytes:
    """Wrap a transaction key with RSAES-PKCS1-v1_5."""
    return public_key.encrypt(transaction_key, padding.PKCS1v15())


def decrypt_transaction_key(private_key: rsa.RSAPrivateKey, encrypted_key: bytes) -> bytes:
    """Unwrap a transaction key, raising ValueError when it is not a 16 byte key for us."""
    # Implicit rejection in OpenSSL 3.2+ may return random bytes instead of failing,
    # so the length check below is what catches a key wrapped for someone else.
    key = private_key.decrypt(encrypted_key, padding.PKCS1v15())
    if len(key) != 16:
        raise ValueError("transaction key could not be decrypted with this key")
    return key


def compress(data: bytes) -> bytes:
    """zlib-compress order data (EBICS compresses before encrypting)."""
    return zlib.compress(data)


def decompress(data: bytes, max_size: int = 1 << 30) -> bytes:
    """zlib-decompress order data, refusing output larger than max_size bytes.

    Raises ValueError on invalid data, on a truncated stream (no end of stream
    reached) and on bytes after the end of the stream.
    """
    decompressor = zlib.decompressobj()
    try:
        out = decompressor.decompress(data, max_size)
    except zlib.error as exc:
        raise ValueError(f"order data is not valid zlib data: {exc}") from exc
    if decompressor.unconsumed_tail:
        raise ValueError(f"decompressed order data exceeds {max_size} bytes")
    if not decompressor.eof:
        raise ValueError("order data is truncated: the zlib stream does not end")
    if decompressor.unused_data:
        raise ValueError("order data has trailing bytes after the zlib stream")
    return out


def certificate_digest(certificate: x509.Certificate) -> bytes:
    """SHA-256 of the DER certificate, the H005 key digest."""
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).digest()


def certificate_from_bytes(data: bytes) -> x509.Certificate:
    """Load a PEM or DER X.509 certificate."""
    if data.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def _key_usage(kind: str) -> x509.KeyUsage:
    signing = kind in (SIGNATURE, AUTHENTICATION)
    return x509.KeyUsage(
        digital_signature=signing,
        content_commitment=kind == SIGNATURE,
        key_encipherment=kind == ENCRYPTION,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def generate_certificate(
    private_key: rsa.RSAPrivateKey,
    kind: str,
    common_name: str,
    country: str | None = None,
    organization: str | None = None,
    not_after: datetime = UNLIMITED,
) -> x509.Certificate:
    """Self-sign a certificate for private_key, as allowed in Germany and Switzerland.

    kind is "A006", "X002" or "E002" and selects the key usage. The certificate is
    SHA-256 signed, not a CA (basicConstraints CA:FALSE) and valid until 9999-12-31
    by default.
    """
    if kind not in (SIGNATURE, AUTHENTICATION, ENCRYPTION):
        raise ValueError(f"unknown key kind {kind!r}")
    attributes = []
    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, kind))
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    name = x509.Name(attributes)
    # Serial: positive, at most 20 octets (RFC 5280), random so reissues differ.
    serial = int.from_bytes(os.urandom(16), "big") >> 1
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.now(timezone.utc).replace(microsecond=0))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(kind), critical=True)
    )
    return builder.sign(private_key, hashes.SHA256())
