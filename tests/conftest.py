"""Shared fixtures: RSA keys are generated once per session to keep the suite fast."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

XSD_DIR = Path(__file__).parent / "xsd" / "H005"

_KEY_POOL: list[rsa.RSAPrivateKey] = []


def pooled_key(index: int) -> rsa.RSAPrivateKey:
    """Return the index-th session-wide 2048 bit RSA key (generated on first use)."""
    while len(_KEY_POOL) <= index:
        _KEY_POOL.append(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    return _KEY_POOL[index]


_SCHEMAS: dict[str, etree.XMLSchema] = {}


def schema(name: str) -> etree.XMLSchema:
    """Load (once) a vendored XSD by file name."""
    if name not in _SCHEMAS:
        parser = etree.XMLParser(load_dtd=False, no_network=True, resolve_entities=False)
        doc = etree.parse(str(XSD_DIR / name), parser)
        _SCHEMAS[name] = etree.XMLSchema(doc)
    return _SCHEMAS[name]


def assert_valid(xml: bytes, schema_name: str = "ebics_H005.xsd") -> None:
    """Fail with the schema error log when xml does not validate."""
    doc = etree.fromstring(xml)
    xsd = schema(schema_name)
    if not xsd.validate(doc):
        pytest.fail(f"{schema_name} rejected {etree.QName(doc).localname}: {xsd.error_log}")


@pytest.fixture
def keys() -> list[rsa.RSAPrivateKey]:
    """Five keys: user A006, X002, E002, then bank X002, E002."""
    return [pooled_key(i) for i in range(5)]
