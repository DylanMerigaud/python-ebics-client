from __future__ import annotations

import hashlib
import zlib
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ebics_client import crypto
from tests.conftest import pooled_key


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 100])
def test_padding_round_trip(size: int) -> None:
    data = bytes(range(256))[:size] if size <= 256 else b"x" * size
    padded = crypto.ebics_pad(data)
    assert len(padded) % 16 == 0
    assert len(padded) > len(data)
    assert crypto.ebics_unpad(padded) == data


def test_padding_full_block_when_aligned() -> None:
    padded = crypto.ebics_pad(b"A" * 16)
    assert len(padded) == 32
    assert padded[16:] == b"\x00" * 15 + b"\x10"


def test_padding_layout() -> None:
    padded = crypto.ebics_pad(b"abc")
    assert padded == b"abc" + b"\x00" * 12 + b"\x0d"


def test_unpad_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        crypto.ebics_unpad(b"\x00" * 15 + b"\x11")
    with pytest.raises(ValueError):
        crypto.ebics_unpad(b"abc")
    with pytest.raises(ValueError):
        crypto.ebics_unpad(b"\x00" * 16)


def test_aes_uses_zero_iv_cbc() -> None:
    key = crypto.generate_transaction_key()
    assert len(key) == 16
    ciphertext = crypto.aes_encrypt(key, b"hello world")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    assert plain == crypto.ebics_pad(b"hello world")
    assert crypto.aes_decrypt(key, ciphertext) == b"hello world"


def test_e002_round_trip() -> None:
    key = pooled_key(2)
    encrypted_key, ciphertext = crypto.e002_encrypt(key.public_key(), b"order data" * 100)
    assert len(encrypted_key) == 256
    assert crypto.e002_decrypt(key, encrypted_key, ciphertext) == b"order data" * 100


def test_e002_wrong_key_fails() -> None:
    encrypted_key, ciphertext = crypto.e002_encrypt(pooled_key(2).public_key(), b"secret")
    with pytest.raises(ValueError):
        crypto.e002_decrypt(pooled_key(1), encrypted_key, ciphertext)


def test_a006_signature_verifies_with_cryptography_directly() -> None:
    key = pooled_key(0)
    data = b"<Document>pain.001</Document>"
    signature = crypto.a006_sign(key, data)
    # A006: RSASSA-PSS, SHA-256, MGF1 SHA-256, salt 32, over the SHA-256 hash of the data.
    key.public_key().verify(
        signature,
        hashlib.sha256(data).digest(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    assert crypto.a006_verify(key.public_key(), signature, data)


def test_a006_wrong_key_or_data_fails() -> None:
    signature = crypto.a006_sign(pooled_key(0), b"data")
    assert not crypto.a006_verify(pooled_key(1).public_key(), signature, b"data")
    assert not crypto.a006_verify(pooled_key(0).public_key(), signature, b"other")


def test_x002_is_pkcs1v15_sha256() -> None:
    key = pooled_key(1)
    signature = crypto.x002_sign(key, b"signed info")
    key.public_key().verify(signature, b"signed info", padding.PKCS1v15(), hashes.SHA256())
    assert crypto.x002_verify(key.public_key(), signature, b"signed info")
    assert not crypto.x002_verify(pooled_key(0).public_key(), signature, b"signed info")
    with pytest.raises(InvalidSignature):
        pooled_key(0).public_key().verify(
            signature, b"signed info", padding.PKCS1v15(), hashes.SHA256()
        )


def test_zlib_helpers() -> None:
    assert zlib.decompress(crypto.compress(b"abc")) == b"abc"
    assert crypto.decompress(zlib.compress(b"abc")) == b"abc"
    with pytest.raises(ValueError):
        crypto.decompress(zlib.compress(b"a" * 1000), max_size=100)


def test_decompress_refuses_truncated_data() -> None:
    compressed = zlib.compress(b"order data " * 100)
    with pytest.raises(ValueError, match="truncated"):
        crypto.decompress(compressed[:-4])  # checksum missing, stream not finished


def test_decompress_refuses_trailing_data() -> None:
    with pytest.raises(ValueError, match="trailing"):
        crypto.decompress(zlib.compress(b"order data") + b"garbage")


def test_self_signed_certificate() -> None:
    key = pooled_key(0)
    cert = crypto.generate_certificate(key, crypto.SIGNATURE, common_name="USER1", country="CH")
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    assert cert.issuer == cert.subject
    assert cert.not_valid_after_utc == datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.critical and basic.value.ca is False
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature and usage.content_commitment
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)
    names = cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    assert names[0].value == "CH"


def test_encryption_certificate_key_usage() -> None:
    cert = crypto.generate_certificate(pooled_key(2), crypto.ENCRYPTION, common_name="USER1")
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.key_encipherment


def test_certificate_digest_is_sha256_of_der() -> None:
    cert = crypto.generate_certificate(pooled_key(1), crypto.AUTHENTICATION, common_name="U")
    der = cert.public_bytes(serialization.Encoding.DER)
    assert crypto.certificate_digest(cert) == hashlib.sha256(der).digest()


def test_key_size_checks() -> None:
    with pytest.raises(ValueError):
        crypto.generate_private_key(1024)
    with pytest.raises(ValueError):
        crypto.check_key_size(pooled_key(0).public_key(), minimum=4096)
    crypto.check_key_size(pooled_key(0).public_key())


def test_order_data_digest_strips_line_breaks() -> None:
    assert crypto.normalize_order_data(b"a\r\nb\nc\x1ad") == b"abcd"
