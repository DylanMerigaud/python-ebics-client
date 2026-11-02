from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from ebics_client import Bank, Keyring, KeyringError, User, crypto, letter
from tests.conftest import pooled_key

USER = User(partner_id="PARTNER1", user_id="USER1")
BANK = Bank(host_id="EBIXHOST", url="https://ebics.example-bank.ch/ebicsweb")


def make_keyring() -> Keyring:
    return Keyring.from_keys(
        USER, pooled_key(0), pooled_key(1), pooled_key(2), subject_country="CH"
    )


def test_generate_creates_three_distinct_keys_and_certs() -> None:
    keyring = Keyring.generate(USER, subject_country="DE")
    keys = [keyring.signature_key, keyring.authentication_key, keyring.encryption_key]
    moduli = {k.public_key().public_numbers().n for k in keys}
    assert len(moduli) == 3
    for key in keys:
        assert key.key_size == 2048
    assert keyring.signature_certificate.public_key().public_numbers() == (
        keyring.signature_key.public_key().public_numbers()
    )
    assert keyring.bank_authentication_certificate is None
    assert keyring.bank_keys_verified is False


def test_save_load_round_trip(tmp_path: Path) -> None:
    keyring = make_keyring()
    bank_cert = crypto.generate_certificate(pooled_key(3), crypto.AUTHENTICATION, "BANK")
    bank_enc = crypto.generate_certificate(pooled_key(4), crypto.ENCRYPTION, "BANK")
    keyring.set_bank_certificates(bank_cert, bank_enc)
    keyring.bank_keys_verified = True
    path = tmp_path / "keys.json"
    keyring.save(path, passphrase="secret")

    loaded = Keyring.load(path, passphrase="secret")
    for name in ("signature", "authentication", "encryption"):
        original = getattr(keyring, f"{name}_key").private_numbers()
        assert getattr(loaded, f"{name}_key").private_numbers() == original
        assert getattr(loaded, f"{name}_certificate") == getattr(keyring, f"{name}_certificate")
    assert loaded.bank_authentication_certificate == bank_cert
    assert loaded.bank_encryption_certificate == bank_enc
    assert loaded.bank_keys_verified is True


def test_saved_file_is_private_and_encrypted(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    make_keyring().save(path, passphrase="secret")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    content = json.loads(path.read_text())
    pem = content["signature"]["key"]
    assert "ENCRYPTED PRIVATE KEY" in pem
    assert "BEGIN PRIVATE KEY" not in path.read_text()


def test_existing_file_mode_is_tightened(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text("{}")
    os.chmod(path, 0o644)
    make_keyring().save(path, passphrase="secret")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_wrong_passphrase_refused(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    make_keyring().save(path, passphrase="secret")
    with pytest.raises(KeyringError):
        Keyring.load(path, passphrase="wrong")


def test_empty_passphrase_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        make_keyring().save(tmp_path / "k.json", passphrase="")


def test_bank_certificates_reset_verification() -> None:
    keyring = make_keyring()
    keyring.bank_keys_verified = True
    bank_cert = crypto.generate_certificate(pooled_key(3), crypto.AUTHENTICATION, "BANK")
    bank_enc = crypto.generate_certificate(pooled_key(4), crypto.ENCRYPTION, "BANK")
    keyring.set_bank_certificates(bank_cert, bank_enc)
    assert keyring.bank_keys_verified is False


def test_replace_certificate_with_ca_issued_one() -> None:
    keyring = make_keyring()
    ca_cert = crypto.generate_certificate(pooled_key(0), crypto.SIGNATURE, "CA ISSUED")
    pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    keyring.load_certificate(crypto.SIGNATURE, pem)
    assert keyring.signature_certificate == ca_cert
    # A certificate for a different key is refused.
    other = crypto.generate_certificate(pooled_key(3), crypto.SIGNATURE, "OTHER")
    with pytest.raises(KeyringError):
        keyring.load_certificate(crypto.SIGNATURE, other.public_bytes(serialization.Encoding.DER))
    with pytest.raises(ValueError):
        keyring.load_certificate("Z001", pem)


def test_letter_contains_the_three_hashes() -> None:
    keyring = make_keyring()
    text = letter.ini_letter(BANK, USER, keyring)
    for cert in (
        keyring.signature_certificate,
        keyring.authentication_certificate,
        keyring.encryption_certificate,
    ):
        assert letter.format_hash(crypto.certificate_digest(cert)) in text
        assert str(cert.serial_number) in text
    for needle in ("EBIXHOST", "PARTNER1", "USER1", "A006", "X002", "E002", "Signature"):
        assert needle in text


def test_format_hash_groups_two_bytes() -> None:
    assert letter.format_hash(bytes(range(32))).startswith("0001 0203 0405")
    assert len(letter.format_hash(bytes(32)).split()) == 16


def test_hia_letter_only_has_x002_and_e002() -> None:
    keyring = make_keyring()
    text = letter.hia_letter(BANK, USER, keyring)
    assert "X002" in text and "E002" in text and "A006" not in text


def test_bank_key_hashes_need_hpb() -> None:
    keyring = make_keyring()
    with pytest.raises(KeyringError):
        letter.bank_key_hashes(keyring)
    bank_cert = crypto.generate_certificate(pooled_key(3), crypto.AUTHENTICATION, "BANK")
    bank_enc = crypto.generate_certificate(pooled_key(4), crypto.ENCRYPTION, "BANK")
    keyring.set_bank_certificates(bank_cert, bank_enc)
    hashes = letter.bank_key_hashes(keyring)
    assert hashes == {
        "X002": letter.format_hash(crypto.certificate_digest(bank_cert)),
        "E002": letter.format_hash(crypto.certificate_digest(bank_enc)),
    }
