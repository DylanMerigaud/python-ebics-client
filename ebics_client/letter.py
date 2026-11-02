"""Initialisation letters (INI and HIA) and the bank key hashes to compare after HPB."""

from __future__ import annotations

from datetime import date

from cryptography import x509

from . import crypto
from .errors import KeyringError
from .keyring import Bank, Keyring, User

__all__ = ["bank_key_hashes", "format_hash", "hia_letter", "ini_letter"]

_RULE = "-" * 72


def format_hash(digest: bytes) -> str:
    """Hex, upper case, grouped by two bytes: "AB12 CD34 ..."."""
    hexed = digest.hex().upper()
    return " ".join(hexed[i : i + 4] for i in range(0, len(hexed), 4))


def _certificate_block(label: str, kind: str, certificate: x509.Certificate) -> list[str]:
    return [
        f"{label} ({kind})",
        f"  Issuer:  {certificate.issuer.rfc4514_string()}",
        f"  Subject: {certificate.subject.rfc4514_string()}",
        f"  Serial:  {certificate.serial_number}",
        "  SHA-256 hash of the certificate:",
        f"  {format_hash(crypto.certificate_digest(certificate))}",
        "",
    ]


def _header(title: str, bank: Bank, user: User, today: date) -> list[str]:
    return [
        title,
        _RULE,
        f"Date:       {today.isoformat()}",
        f"Host ID:    {bank.host_id}",
        f"Bank URL:   {bank.url}",
        f"Partner ID: {user.partner_id}",
        f"User ID:    {user.user_id}",
        "Protocol:   EBICS 3.0 (H005)",
        "",
    ]


def _signature_lines() -> list[str]:
    return [
        "I confirm that the certificates above are mine.",
        "",
        "Place and date: ______________________________",
        "",
        "Signature:      ______________________________",
        "",
    ]


def _ini_section(bank: Bank, user: User, keyring: Keyring, today: date) -> list[str]:
    lines = _header("EBICS initialisation letter INI (electronic signature)", bank, user, today)
    lines += _certificate_block("Signature certificate", crypto.SIGNATURE, keyring.signature_certificate)
    return lines + _signature_lines()


def _hia_section(bank: Bank, user: User, keyring: Keyring, today: date) -> list[str]:
    lines = _header(
        "EBICS initialisation letter HIA (authentication and encryption)", bank, user, today
    )
    lines += _certificate_block(
        "Authentication certificate", crypto.AUTHENTICATION, keyring.authentication_certificate
    )
    lines += _certificate_block(
        "Encryption certificate", crypto.ENCRYPTION, keyring.encryption_certificate
    )
    return lines + _signature_lines()


def ini_letter(bank: Bank, user: User, keyring: Keyring, today: date | None = None) -> str:
    """Text letters to sign and send to the bank after INI and HIA (both sections).

    The bank compares the SHA-256 hashes printed here with the certificates it
    received before activating the user.
    """
    day = today or date.today()
    lines = _ini_section(bank, user, keyring, day) + ["", ""] + _hia_section(bank, user, keyring, day)
    return "\n".join(lines)


def hia_letter(bank: Bank, user: User, keyring: Keyring, today: date | None = None) -> str:
    """The HIA letter alone (authentication and encryption certificates)."""
    return "\n".join(_hia_section(bank, user, keyring, today or date.today()))


def bank_key_hashes(keyring: Keyring) -> dict[str, str]:
    """Hashes of the bank's X002 and E002 certificates, to compare with the bank's letter."""
    if keyring.bank_authentication_certificate is None or keyring.bank_encryption_certificate is None:
        raise KeyringError(text="the bank keys are unknown, run hpb() first")
    return {
        crypto.AUTHENTICATION: format_hash(
            crypto.certificate_digest(keyring.bank_authentication_certificate)
        ),
        crypto.ENCRYPTION: format_hash(crypto.certificate_digest(keyring.bank_encryption_certificate)),
    }
