"""Parsing of EBICS H005 responses: return codes, transaction state, order data."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from . import crypto
from .errors import (
    RETURN_CODES,
    EbicsBusinessError,
    EbicsError,
    EbicsTechnicalError,
    NoDownloadData,
)
from .requests import H000_NS, H005_NS
from .xmlsig import DS_NS

__all__ = [
    "BankCertificates",
    "ProtocolVersion",
    "Response",
    "decode_segments",
    "decrypt_order_data",
    "parse_hev",
    "parse_hpb_order_data",
    "parse_response",
    "parse_xml",
]

#: Technical codes that mean success (or the expected answer to a receipt).
TECHNICAL_OK = frozenset({"000000", "011000", "011001"})
#: Business codes that mean success; 031001 (order params ignored) and 011301
#: (no online checks) are warnings.
BUSINESS_OK = frozenset({"", "000000", "011000", "011301", "031001"})

_ROOTS = ("ebicsResponse", "ebicsKeyManagementResponse")


def _parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False, remove_comments=False
    )


def parse_xml(data: bytes) -> etree._Element:
    """Parse bytes from the bank, refusing DTDs and entity declarations."""
    try:
        root = etree.fromstring(data, _parser())
    except etree.XMLSyntaxError as exc:
        raise EbicsError(text=f"the bank's answer is not XML: {exc}") from exc
    tree = root.getroottree()
    if getattr(tree.docinfo, "doctype", "") or tree.docinfo.internalDTD is not None:
        raise EbicsError(text="the bank's answer carries a DTD, refused")
    return root


@dataclass(frozen=True)
class ProtocolVersion:
    """An EBICS protocol version the bank supports, e.g. ("H005", "03.00")."""

    protocol: str
    version: str


@dataclass(frozen=True)
class BankCertificates:
    """The bank's certificates from an HPB response."""

    authentication: x509.Certificate
    encryption: x509.Certificate
    host_id: str


def _text(root: etree._Element, path: str) -> str | None:
    found = root.find(path)
    if found is None:
        return None
    return (found.text or "").strip()


def _e(path: str) -> str:
    return "/".join(
        f"{{{H005_NS}}}{part}" if part not in (".", "..") else part for part in path.split("/")
    )


@dataclass
class Response:
    """A parsed ebicsResponse or ebicsKeyManagementResponse."""

    root: etree._Element
    kind: str
    technical_code: str
    report_text: str
    business_code: str
    phase: str | None = None
    transaction_id: str | None = None
    num_segments: int | None = None
    segment_number: int | None = None
    last_segment: bool = False
    order_id: str | None = None
    order_data: str | None = None
    transaction_key: bytes | None = None
    encryption_pubkey_digest: bytes | None = None

    def raise_for_codes(self) -> None:
        """Raise the matching EbicsError unless both return codes mean success."""
        if self.technical_code not in TECHNICAL_OK:
            raise EbicsTechnicalError(self.technical_code, self.report_text)
        if self.business_code == "090005":
            raise NoDownloadData()
        if self.business_code not in BUSINESS_OK:
            raise EbicsBusinessError(self.business_code, RETURN_CODES.get(self.business_code, ""))


def _int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise EbicsError(text=f"invalid number in the bank's answer: {value!r}") from exc


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode("".join(value.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EbicsError(text="invalid base64 in the bank's answer") from exc


def parse_response(data: bytes) -> Response:
    """Parse an H005 response; codes are read, not checked (see raise_for_codes)."""
    root = parse_xml(data)
    qname = etree.QName(root)
    if qname.namespace != H005_NS or qname.localname not in _ROOTS:
        raise EbicsError(text=f"unexpected answer from the bank: {qname.localname}")
    technical = _text(root, _e("header/mutable/ReturnCode"))
    if technical is None:
        raise EbicsError(text="the bank's answer has no ReturnCode")
    segment = root.find(_e("header/mutable/SegmentNumber"))
    key = _text(root, _e("body/DataTransfer/DataEncryptionInfo/TransactionKey"))
    digest = _text(root, _e("body/DataTransfer/DataEncryptionInfo/EncryptionPubKeyDigest"))
    return Response(
        root=root,
        kind=qname.localname,
        technical_code=technical,
        report_text=_text(root, _e("header/mutable/ReportText")) or "",
        business_code=_text(root, _e("body/ReturnCode")) or "",
        phase=_text(root, _e("header/mutable/TransactionPhase")),
        transaction_id=_text(root, _e("header/static/TransactionID")),
        num_segments=_int(_text(root, _e("header/static/NumSegments"))),
        segment_number=_int((segment.text or "").strip()) if segment is not None else None,
        last_segment=segment is not None and segment.get("lastSegment") in ("true", "1"),
        order_id=_text(root, _e("header/mutable/OrderID")),
        order_data=_text(root, _e("body/DataTransfer/OrderData")),
        transaction_key=_b64decode(key) if key else None,
        encryption_pubkey_digest=_b64decode(digest) if digest else None,
    )


def parse_hev(data: bytes) -> list[ProtocolVersion]:
    """Parse an ebicsHEVResponse (H000) into the supported protocol versions."""
    root = parse_xml(data)
    if root.tag != f"{{{H000_NS}}}ebicsHEVResponse":
        raise EbicsError(text="unexpected answer to HEV")
    code = root.findtext(f"{{{H000_NS}}}SystemReturnCode/{{{H000_NS}}}ReturnCode", "").strip()
    text = root.findtext(f"{{{H000_NS}}}SystemReturnCode/{{{H000_NS}}}ReportText", "").strip()
    if code != "000000":
        raise EbicsTechnicalError(code, text)
    return [
        ProtocolVersion(node.get("ProtocolVersion", ""), (node.text or "").strip())
        for node in root.iter(f"{{{H000_NS}}}VersionNumber")
    ]


def decode_segments(segments: list[str]) -> bytes:
    """Join base64 order data segments into the encrypted bytes.

    Banks split either the encrypted bytes (each segment is padded base64) or the
    base64 text; both are accepted.
    """
    cleaned = ["".join(segment.split()) for segment in segments]
    if all(len(segment) % 4 == 0 for segment in cleaned):
        return b"".join(_b64decode(segment) for segment in cleaned)
    return _b64decode("".join(cleaned))


def decrypt_order_data(
    private_key: rsa.RSAPrivateKey, encrypted_key: bytes, ciphertext: bytes
) -> bytes:
    """Decrypt (E002) and decompress order data sent by the bank."""
    try:
        compressed = crypto.e002_decrypt(private_key, encrypted_key, ciphertext)
        return crypto.decompress(compressed)
    except ValueError as exc:
        raise EbicsError(text=f"order data could not be decrypted: {exc}") from exc


def _certificate(
    root: etree._Element, info: str, version_tag: str, version: str
) -> x509.Certificate:
    element = root.find(f"{{{H005_NS}}}{info}")
    if element is None:
        raise EbicsError(text=f"HPB answer has no {info}")
    found = (element.findtext(f"{{{H005_NS}}}{version_tag}") or "").strip()
    if found != version:
        raise EbicsError(
            text=f"HPB answer offers {version_tag} {found!r}, only {version} is supported"
        )
    der = element.findtext(f"{{{DS_NS}}}X509Data/{{{DS_NS}}}X509Certificate")
    if not der:
        raise EbicsError(text=f"HPB answer has no certificate in {info}")
    try:
        return x509.load_der_x509_certificate(_b64decode(der))
    except ValueError as exc:
        raise EbicsError(text=f"HPB answer holds an invalid certificate in {info}") from exc


def parse_hpb_order_data(data: bytes) -> BankCertificates:
    """Read the bank's X002 and E002 certificates from HPBResponseOrderData."""
    root = parse_xml(data)
    if root.tag != f"{{{H005_NS}}}HPBResponseOrderData":
        raise EbicsError(text="HPB order data is not HPBResponseOrderData")
    return BankCertificates(
        authentication=_certificate(
            root, "AuthenticationPubKeyInfo", "AuthenticationVersion", "X002"
        ),
        encryption=_certificate(root, "EncryptionPubKeyInfo", "EncryptionVersion", "E002"),
        host_id=(root.findtext(f"{{{H005_NS}}}HostID") or "").strip(),
    )
