"""Bank and user identities, and the keyring holding the user's and the bank's keys."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import crypto
from .errors import KeyringError

__all__ = ["Bank", "Keyring", "User"]

_FORMAT = "python-ebics-client keyring"
_FORMAT_VERSION = 1


@dataclass(frozen=True)
class Bank:
    """An EBICS host: its HostID and the URL of its EBICS endpoint."""

    host_id: str
    url: str


@dataclass(frozen=True)
class User:
    """An EBICS subscriber: PartnerID (customer) and UserID, optional SystemID."""

    partner_id: str
    user_id: str
    system_id: str | None = None


def _passphrase_bytes(passphrase: str | bytes) -> bytes:
    data = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
    if not data:
        raise ValueError("a non-empty passphrase is required to protect the keyring")
    return data


def _same_key(certificate: x509.Certificate, key: rsa.RSAPrivateKey) -> bool:
    public = certificate.public_key()
    return (
        isinstance(public, rsa.RSAPublicKey)
        and public.public_numbers() == key.public_key().public_numbers()
    )


def _rsa_public(certificate: x509.Certificate) -> rsa.RSAPublicKey:
    public = certificate.public_key()
    if not isinstance(public, rsa.RSAPublicKey):
        raise KeyringError(text="EBICS certificates must carry an RSA key")
    crypto.check_key_size(public)
    return public


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


class Keyring:
    """The user's A006, X002 and E002 keys with their certificates, and the bank's keys.

    bank_keys_verified must only be set to True after the bank certificate hashes
    (see letter.bank_key_hashes) were compared with the ones the bank published.
    """

    def __init__(
        self,
        signature_key: rsa.RSAPrivateKey,
        signature_certificate: x509.Certificate,
        authentication_key: rsa.RSAPrivateKey,
        authentication_certificate: x509.Certificate,
        encryption_key: rsa.RSAPrivateKey,
        encryption_certificate: x509.Certificate,
        bank_authentication_certificate: x509.Certificate | None = None,
        bank_encryption_certificate: x509.Certificate | None = None,
        bank_keys_verified: bool = False,
    ) -> None:
        pairs = (
            (crypto.SIGNATURE, signature_key, signature_certificate),
            (crypto.AUTHENTICATION, authentication_key, authentication_certificate),
            (crypto.ENCRYPTION, encryption_key, encryption_certificate),
        )
        for kind, key, certificate in pairs:
            crypto.check_key_size(key.public_key())
            if not _same_key(certificate, key):
                raise KeyringError(text=f"the {kind} certificate does not match the {kind} key")
        self.signature_key = signature_key
        self.signature_certificate = signature_certificate
        self.authentication_key = authentication_key
        self.authentication_certificate = authentication_certificate
        self.encryption_key = encryption_key
        self.encryption_certificate = encryption_certificate
        self.bank_authentication_certificate = bank_authentication_certificate
        self.bank_encryption_certificate = bank_encryption_certificate
        self.bank_keys_verified = bank_keys_verified

    @classmethod
    def generate(
        cls,
        user: User,
        subject_country: str | None = None,
        key_size: int = crypto.MIN_KEY_SIZE,
        organization: str | None = None,
    ) -> Keyring:
        """Generate the three user keys and self-signed certificates for them."""
        return cls.from_keys(
            user,
            crypto.generate_private_key(key_size),
            crypto.generate_private_key(key_size),
            crypto.generate_private_key(key_size),
            subject_country=subject_country,
            organization=organization,
        )

    @classmethod
    def from_keys(
        cls,
        user: User,
        signature_key: rsa.RSAPrivateKey,
        authentication_key: rsa.RSAPrivateKey,
        encryption_key: rsa.RSAPrivateKey,
        subject_country: str | None = None,
        organization: str | None = None,
    ) -> Keyring:
        """Build a keyring from existing keys, issuing self-signed certificates."""

        def issue(key: rsa.RSAPrivateKey, kind: str) -> x509.Certificate:
            return crypto.generate_certificate(
                key,
                kind,
                common_name=user.user_id,
                country=subject_country,
                organization=organization or user.partner_id,
            )

        return cls(
            signature_key,
            issue(signature_key, crypto.SIGNATURE),
            authentication_key,
            issue(authentication_key, crypto.AUTHENTICATION),
            encryption_key,
            issue(encryption_key, crypto.ENCRYPTION),
        )

    # Certificates -------------------------------------------------------------

    def load_certificate(self, kind: str, data: bytes) -> x509.Certificate:
        """Replace a user certificate (PEM or DER), e.g. one issued by a CA for H3K.

        kind is "A006", "X002" or "E002"; the certificate must carry that key.
        """
        attribute = {
            crypto.SIGNATURE: "signature",
            crypto.AUTHENTICATION: "authentication",
            crypto.ENCRYPTION: "encryption",
        }.get(kind)
        if attribute is None:
            raise ValueError(f"unknown key kind {kind!r}, use A006, X002 or E002")
        certificate = crypto.certificate_from_bytes(data)
        if not _same_key(certificate, getattr(self, f"{attribute}_key")):
            raise KeyringError(text=f"the certificate does not carry the {kind} key")
        setattr(self, f"{attribute}_certificate", certificate)
        return certificate

    def set_bank_certificates(
        self, authentication: x509.Certificate, encryption: x509.Certificate
    ) -> None:
        """Store the bank's X002 and E002 certificates; they start unverified."""
        _rsa_public(authentication)
        _rsa_public(encryption)
        self.bank_authentication_certificate = authentication
        self.bank_encryption_certificate = encryption
        self.bank_keys_verified = False

    @property
    def has_bank_keys(self) -> bool:
        """True once the bank certificates are known (after HPB)."""
        return (
            self.bank_authentication_certificate is not None
            and self.bank_encryption_certificate is not None
        )

    def bank_certificates(self) -> tuple[x509.Certificate, x509.Certificate]:
        """The bank's (X002, E002) certificates, raising KeyringError before HPB."""
        authentication = self.bank_authentication_certificate
        encryption = self.bank_encryption_certificate
        if authentication is None or encryption is None:
            raise KeyringError(text="the bank keys are unknown, run hpb() first")
        return authentication, encryption

    def bank_authentication_key(self) -> rsa.RSAPublicKey:
        """The bank's X002 public key, raising KeyringError before HPB."""
        if self.bank_authentication_certificate is None:
            raise KeyringError(text="the bank keys are unknown, run hpb() first")
        return _rsa_public(self.bank_authentication_certificate)

    def bank_encryption_key(self) -> rsa.RSAPublicKey:
        """The bank's E002 public key, raising KeyringError before HPB."""
        if self.bank_encryption_certificate is None:
            raise KeyringError(text="the bank keys are unknown, run hpb() first")
        return _rsa_public(self.bank_encryption_certificate)

    # Persistence --------------------------------------------------------------

    def to_dict(self, passphrase: str | bytes) -> dict[str, Any]:
        """Serialise to a JSON-ready dict, private keys encrypted with passphrase."""
        algorithm = serialization.BestAvailableEncryption(_passphrase_bytes(passphrase))

        def key_pem(key: rsa.RSAPrivateKey) -> str:
            return key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, algorithm
            ).decode("ascii")

        bank: dict[str, str | None] = {
            "authentication": _pem(self.bank_authentication_certificate)
            if self.bank_authentication_certificate
            else None,
            "encryption": _pem(self.bank_encryption_certificate)
            if self.bank_encryption_certificate
            else None,
        }
        return {
            "format": _FORMAT,
            "version": _FORMAT_VERSION,
            "signature": {
                "key": key_pem(self.signature_key),
                "certificate": _pem(self.signature_certificate),
            },
            "authentication": {
                "key": key_pem(self.authentication_key),
                "certificate": _pem(self.authentication_certificate),
            },
            "encryption": {
                "key": key_pem(self.encryption_key),
                "certificate": _pem(self.encryption_certificate),
            },
            "bank": bank,
            "bank_keys_verified": self.bank_keys_verified,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], passphrase: str | bytes) -> Keyring:
        """Rebuild a keyring from to_dict output, raising KeyringError on a bad passphrase."""
        if data.get("format") != _FORMAT or data.get("version") != _FORMAT_VERSION:
            raise KeyringError(text="not a python-ebics-client keyring (version 1)")
        secret = _passphrase_bytes(passphrase)

        def key(entry: dict[str, str]) -> rsa.RSAPrivateKey:
            try:
                loaded = serialization.load_pem_private_key(entry["key"].encode(), secret)
            except (ValueError, TypeError) as exc:
                raise KeyringError(text="wrong passphrase or damaged keyring") from exc
            if not isinstance(loaded, rsa.RSAPrivateKey):
                raise KeyringError(text="keyring holds a non-RSA key")
            return loaded

        def cert(pem: str | None) -> x509.Certificate | None:
            return x509.load_pem_x509_certificate(pem.encode()) if pem else None

        def user_cert(entry: dict[str, str]) -> x509.Certificate:
            return x509.load_pem_x509_certificate(entry["certificate"].encode())

        bank = data.get("bank") or {}
        return cls(
            key(data["signature"]),
            user_cert(data["signature"]),
            key(data["authentication"]),
            user_cert(data["authentication"]),
            key(data["encryption"]),
            user_cert(data["encryption"]),
            bank_authentication_certificate=cert(bank.get("authentication")),
            bank_encryption_certificate=cert(bank.get("encryption")),
            bank_keys_verified=bool(data.get("bank_keys_verified", False)),
        )

    def save(self, path: str | os.PathLike[str], passphrase: str | bytes) -> None:
        """Write the keyring as JSON to path with mode 600, keys encrypted by passphrase."""
        payload = json.dumps(self.to_dict(passphrase), indent=2).encode("utf-8")
        target = Path(path)
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            if hasattr(os, "fchmod"):
                # O_CREAT's mode only applies to new files: tighten an existing one too.
                os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)

    @classmethod
    def load(cls, path: str | os.PathLike[str], passphrase: str | bytes) -> Keyring:
        """Read a keyring written by save."""
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return cls.from_dict(data, passphrase)
