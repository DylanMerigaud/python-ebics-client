"""Builders for the EBICS H005 requests: HEV, INI, HIA, H3K, HPB, BTD and BTU."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from lxml import etree

from . import crypto, xmlsig
from .keyring import Bank, Keyring, User
from .service import Service

__all__ = [
    "H000_NS",
    "H005_NS",
    "S002_NS",
    "SEGMENT_SIZE",
    "RequestContext",
    "UploadPayload",
    "build_btd_init",
    "build_btu_init",
    "build_download_transfer",
    "build_h3k",
    "build_hev",
    "build_hia",
    "build_hpb",
    "build_ini",
    "build_receipt",
    "build_upload_transfer",
    "prepare_upload",
]

H005_NS = xmlsig.H005_NS
DS_NS = xmlsig.DS_NS
S002_NS = "http://www.ebics.org/S002"
H000_NS = "http://www.ebics.org/H000"
SHA256_URI = "http://www.w3.org/2001/04/xmlenc#sha256"

#: Maximum size of one segment of base64 order data (EBICS: 1 MB).
SEGMENT_SIZE = 1024 * 1024
# Raw bytes per segment: a multiple of 3 whose base64 is exactly SEGMENT_SIZE long, so
# every segment is valid base64 on its own and the concatenation is too.
_RAW_SEGMENT = SEGMENT_SIZE // 4 * 3

_PRODUCT = "python-ebics-client 0.1.0"
_SECURITY_MEDIUM = "0000"


@dataclass(frozen=True)
class RequestContext:
    """Who sends the request: host, subscriber and product identification."""

    host_id: str
    partner_id: str
    user_id: str
    system_id: str | None = None
    product: str = _PRODUCT
    language: str = "en"

    @classmethod
    def create(
        cls, bank: Bank, user: User, product: str = _PRODUCT, language: str = "en"
    ) -> RequestContext:
        """Build a context from a Bank and a User."""
        return cls(bank.host_id, user.partner_id, user.user_id, user.system_id, product, language)


@dataclass
class UploadPayload:
    """Everything a BTU needs, computed once: key, signature, digest and segments."""

    transaction_key: bytes
    digest: bytes
    signature_data: bytes
    segments: list[str] = field(default_factory=list)


# Element helpers ---------------------------------------------------------------


def _e(name: str) -> str:
    return f"{{{H005_NS}}}{name}"


def _sub(
    parent: etree._Element, name: str, text: str | None = None, **attrib: str
) -> etree._Element:
    element = etree.SubElement(parent, name, attrib)
    if text is not None:
        element.text = text
    return element


def _new(tag: str, default_ns: str, **prefixes: str) -> etree._Element:
    """Root element with default_ns as the default namespace and extra prefixes."""
    nsmap: dict[str | None, str] = {None: default_ns}
    nsmap.update(prefixes)
    # lxml accepts None as the default-namespace key; its stubs do not say so.
    return etree.Element(tag, nsmap=cast("dict[str, str]", nsmap))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _nonce() -> str:
    return secrets.token_hex(16).upper()


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _serialize(root: etree._Element) -> bytes:
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _root(name: str, secured: bool) -> etree._Element:
    root = _new(_e(name), H005_NS, ds=DS_NS) if secured else _new(_e(name), H005_NS)
    root.set("Version", "H005")
    root.set("Revision", "1")
    return root


def _header(root: etree._Element) -> tuple[etree._Element, etree._Element]:
    header = _sub(root, _e("header"), authenticate="true")
    return header, _sub(header, _e("static"))


def _subscriber(static: etree._Element, ctx: RequestContext, nonce: bool) -> None:
    _sub(static, _e("HostID"), ctx.host_id)
    if nonce:
        _sub(static, _e("Nonce"), _nonce())
        _sub(static, _e("Timestamp"), _timestamp())
    _sub(static, _e("PartnerID"), ctx.partner_id)
    _sub(static, _e("UserID"), ctx.user_id)
    if ctx.system_id:
        _sub(static, _e("SystemID"), ctx.system_id)
    _sub(static, _e("Product"), ctx.product, Language=ctx.language)


def _x509_data(parent: etree._Element, certificate: x509.Certificate) -> None:
    data = etree.SubElement(parent, f"{{{DS_NS}}}X509Data", nsmap={"ds": DS_NS})
    issuer_serial = etree.SubElement(data, f"{{{DS_NS}}}X509IssuerSerial")
    _sub(issuer_serial, f"{{{DS_NS}}}X509IssuerName", certificate.issuer.rfc4514_string())
    _sub(issuer_serial, f"{{{DS_NS}}}X509SerialNumber", str(certificate.serial_number))
    der = certificate.public_bytes(serialization.Encoding.DER)
    _sub(data, f"{{{DS_NS}}}X509Certificate", _b64(der))


def _service(parent: etree._Element, service: Service) -> None:
    # Element order fixed by RestrictedServiceType (ebics_orders_H005.xsd).
    element = _sub(parent, _e("Service"))
    _sub(element, _e("ServiceName"), service.name)
    if service.scope:
        _sub(element, _e("Scope"), service.scope)
    if service.option:
        _sub(element, _e("ServiceOption"), service.option)
    if service.container:
        _sub(element, _e("Container"), containerType=service.container)
    attrib = {}
    if service.variant:
        attrib["variant"] = service.variant
    if service.msg_version:
        attrib["version"] = service.msg_version
    if service.format:
        attrib["format"] = service.format
    _sub(element, _e("MsgName"), service.msg_name, **attrib)


def _bank_digests(static: etree._Element, keyring: Keyring) -> None:
    authentication, encryption = keyring.bank_certificates()
    digests = _sub(static, _e("BankPubKeyDigests"))
    _sub(
        digests,
        _e("Authentication"),
        _b64(crypto.certificate_digest(authentication)),
        Version=crypto.AUTHENTICATION,
        Algorithm=SHA256_URI,
    )
    _sub(
        digests,
        _e("Encryption"),
        _b64(crypto.certificate_digest(encryption)),
        Version=crypto.ENCRYPTION,
        Algorithm=SHA256_URI,
    )


def _order_xml(root: etree._Element) -> bytes:
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _user_signature_data(ctx: RequestContext, keyring: Keyring, order_data: bytes) -> bytes:
    """UserSignatureData (S002) with the A006 signature of order_data."""
    signature = crypto.a006_sign(keyring.signature_key, crypto.normalize_order_data(order_data))
    root = _new(f"{{{S002_NS}}}UserSignatureData", S002_NS)
    data = _sub(root, f"{{{S002_NS}}}OrderSignatureData")
    _sub(data, f"{{{S002_NS}}}SignatureVersion", crypto.SIGNATURE)
    _sub(data, f"{{{S002_NS}}}SignatureValue", _b64(signature))
    _sub(data, f"{{{S002_NS}}}PartnerID", ctx.partner_id)
    _sub(data, f"{{{S002_NS}}}UserID", ctx.user_id)
    return _order_xml(root)


# Key management ----------------------------------------------------------------


def build_hev(host_id: str) -> bytes:
    """HEV: ask the bank which EBICS versions it supports (H000, unauthenticated)."""
    root = _new(f"{{{H000_NS}}}ebicsHEVRequest", H000_NS)
    _sub(root, f"{{{H000_NS}}}HostID", host_id)
    return _serialize(root)


def _unsecured(ctx: RequestContext, order_type: str, order_data: bytes) -> bytes:
    root = _root("ebicsUnsecuredRequest", secured=False)
    header, static = _header(root)
    _subscriber(static, ctx, nonce=False)
    details = _sub(static, _e("OrderDetails"))
    _sub(details, _e("AdminOrderType"), order_type)
    _sub(static, _e("SecurityMedium"), _SECURITY_MEDIUM)
    _sub(header, _e("mutable"))
    transfer = _sub(_sub(root, _e("body")), _e("DataTransfer"))
    _sub(transfer, _e("OrderData"), _b64(crypto.compress(order_data)))
    return _serialize(root)


def ini_order_data(ctx: RequestContext, keyring: Keyring) -> bytes:
    """SignaturePubKeyOrderData (S002) carrying the A006 certificate."""
    root = _new(f"{{{S002_NS}}}SignaturePubKeyOrderData", S002_NS, ds=DS_NS)
    info = _sub(root, f"{{{S002_NS}}}SignaturePubKeyInfo")
    _x509_data(info, keyring.signature_certificate)
    _sub(info, f"{{{S002_NS}}}SignatureVersion", crypto.SIGNATURE)
    _sub(root, f"{{{S002_NS}}}PartnerID", ctx.partner_id)
    _sub(root, f"{{{S002_NS}}}UserID", ctx.user_id)
    return _order_xml(root)


def hia_order_data(ctx: RequestContext, keyring: Keyring) -> bytes:
    """HIARequestOrderData carrying the X002 and E002 certificates."""
    root = _new(_e("HIARequestOrderData"), H005_NS, ds=DS_NS)
    auth = _sub(root, _e("AuthenticationPubKeyInfo"))
    _x509_data(auth, keyring.authentication_certificate)
    _sub(auth, _e("AuthenticationVersion"), crypto.AUTHENTICATION)
    enc = _sub(root, _e("EncryptionPubKeyInfo"))
    _x509_data(enc, keyring.encryption_certificate)
    _sub(enc, _e("EncryptionVersion"), crypto.ENCRYPTION)
    _sub(root, _e("PartnerID"), ctx.partner_id)
    _sub(root, _e("UserID"), ctx.user_id)
    return _order_xml(root)


def h3k_order_data(ctx: RequestContext, keyring: Keyring) -> bytes:
    """H3KRequestOrderData carrying the three (usually CA-issued) certificates."""
    root = _new(_e("H3KRequestOrderData"), H005_NS, ds=DS_NS)
    for name, version_name, version, certificate in (
        (
            "SignatureCertificateInfo",
            "SignatureVersion",
            crypto.SIGNATURE,
            keyring.signature_certificate,
        ),
        (
            "AuthenticationCertificateInfo",
            "AuthenticationVersion",
            crypto.AUTHENTICATION,
            keyring.authentication_certificate,
        ),
        (
            "EncryptionCertificateInfo",
            "EncryptionVersion",
            crypto.ENCRYPTION,
            keyring.encryption_certificate,
        ),
    ):
        info = _sub(root, _e(name))
        _x509_data(info, certificate)
        _sub(info, _e(version_name), version)
    _sub(root, _e("PartnerID"), ctx.partner_id)
    _sub(root, _e("UserID"), ctx.user_id)
    return _order_xml(root)


def build_ini(ctx: RequestContext, keyring: Keyring) -> bytes:
    """INI: send the A006 certificate (ebicsUnsecuredRequest)."""
    return _unsecured(ctx, "INI", ini_order_data(ctx, keyring))


def build_hia(ctx: RequestContext, keyring: Keyring) -> bytes:
    """HIA: send the X002 and E002 certificates (ebicsUnsecuredRequest)."""
    return _unsecured(ctx, "HIA", hia_order_data(ctx, keyring))


def build_h3k(ctx: RequestContext, keyring: Keyring) -> bytes:
    """H3K: send all three certificates in one ebicsUnsignedRequest signed with A006.

    The order data and its UserSignatureData are compressed and base64 encoded but
    not encrypted: the bank's encryption key is not known yet.
    """
    order_data = h3k_order_data(ctx, keyring)
    root = _root("ebicsUnsignedRequest", secured=False)
    header, static = _header(root)
    _subscriber(static, ctx, nonce=False)
    details = _sub(static, _e("OrderDetails"))
    _sub(details, _e("AdminOrderType"), "H3K")
    _sub(static, _e("SecurityMedium"), _SECURITY_MEDIUM)
    _sub(header, _e("mutable"))
    transfer = _sub(_sub(root, _e("body")), _e("DataTransfer"))
    signature = _user_signature_data(ctx, keyring, order_data)
    _sub(transfer, _e("SignatureData"), _b64(crypto.compress(signature)), authenticate="true")
    _sub(transfer, _e("OrderData"), _b64(crypto.compress(order_data)))
    return _serialize(root)


def build_hpb(ctx: RequestContext, keyring: Keyring) -> bytes:
    """HPB: fetch the bank's certificates (ebicsNoPubKeyDigestsRequest, X002 signed)."""
    root = _root("ebicsNoPubKeyDigestsRequest", secured=True)
    header, static = _header(root)
    _subscriber(static, ctx, nonce=True)
    details = _sub(static, _e("OrderDetails"))
    _sub(details, _e("AdminOrderType"), "HPB")
    _sub(static, _e("SecurityMedium"), _SECURITY_MEDIUM)
    _sub(header, _e("mutable"))
    _sub(root, _e("body"))
    xmlsig.sign(root, keyring.authentication_key)
    return _serialize(root)


# Business transactions ---------------------------------------------------------


def _secured_init(
    ctx: RequestContext, order_type: str
) -> tuple[etree._Element, etree._Element, etree._Element, etree._Element]:
    root = _root("ebicsRequest", secured=True)
    header, static = _header(root)
    _subscriber(static, ctx, nonce=True)
    details = _sub(static, _e("OrderDetails"))
    _sub(details, _e("AdminOrderType"), order_type)
    return root, header, static, details


def _finish_init(
    root: etree._Element,
    header: etree._Element,
    static: etree._Element,
    keyring: Keyring,
    num_segments: int | None = None,
) -> etree._Element:
    _bank_digests(static, keyring)
    _sub(static, _e("SecurityMedium"), _SECURITY_MEDIUM)
    if num_segments is not None:
        _sub(static, _e("NumSegments"), str(num_segments))
    mutable = _sub(header, _e("mutable"))
    _sub(mutable, _e("TransactionPhase"), "Initialisation")
    return _sub(root, _e("body"))


def build_btd_init(
    ctx: RequestContext,
    keyring: Keyring,
    service: Service,
    start: date | None = None,
    end: date | None = None,
) -> bytes:
    """BTD initialisation: request a download for service, optionally for a date range."""
    if (start is None) != (end is None):
        raise ValueError("give both start and end, or neither")
    root, header, static, details = _secured_init(ctx, "BTD")
    params = _sub(details, _e("BTDOrderParams"))
    _service(params, service)
    if start is not None and end is not None:
        if start > end:
            raise ValueError("start must not be after end")
        date_range = _sub(params, _e("DateRange"))
        _sub(date_range, _e("Start"), start.isoformat())
        _sub(date_range, _e("End"), end.isoformat())
    _finish_init(root, header, static, keyring)
    xmlsig.sign(root, keyring.authentication_key)
    return _serialize(root)


def _transaction(
    ctx: RequestContext, transaction_id: str, phase: str
) -> tuple[etree._Element, etree._Element]:
    root = _root("ebicsRequest", secured=True)
    header, static = _header(root)
    _sub(static, _e("HostID"), ctx.host_id)
    _sub(static, _e("TransactionID"), transaction_id)
    mutable = _sub(header, _e("mutable"))
    _sub(mutable, _e("TransactionPhase"), phase)
    return root, mutable


def build_download_transfer(
    ctx: RequestContext, keyring: Keyring, transaction_id: str, segment: int, last: bool
) -> bytes:
    """BTD transfer: ask for segment number segment of a download."""
    root, mutable = _transaction(ctx, transaction_id, "Transfer")
    _sub(mutable, _e("SegmentNumber"), str(segment), lastSegment="true" if last else "false")
    _sub(root, _e("body"))
    xmlsig.sign(root, keyring.authentication_key)
    return _serialize(root)


def build_receipt(
    ctx: RequestContext, keyring: Keyring, transaction_id: str, acknowledged: bool = True
) -> bytes:
    """Receipt phase of a download: ReceiptCode 0 acknowledges, 1 refuses."""
    root, _ = _transaction(ctx, transaction_id, "Receipt")
    receipt = _sub(_sub(root, _e("body")), _e("TransferReceipt"), authenticate="true")
    _sub(receipt, _e("ReceiptCode"), "0" if acknowledged else "1")
    xmlsig.sign(root, keyring.authentication_key)
    return _serialize(root)


def prepare_upload(ctx: RequestContext, keyring: Keyring, order_data: bytes) -> UploadPayload:
    """Sign, compress, encrypt and segment order data for a BTU.

    The A006 signature and the DataDigest cover the order data with CR, LF and
    Ctrl-Z removed (the EBICS hash rule); the data itself is sent unchanged, so
    non-XML formats keep their line breaks.
    """
    transaction_key = crypto.generate_transaction_key()
    digest = hashlib.sha256(crypto.normalize_order_data(order_data)).digest()
    signature = _user_signature_data(ctx, keyring, order_data)
    signature_data = crypto.aes_encrypt(transaction_key, crypto.compress(signature))
    encrypted = crypto.aes_encrypt(transaction_key, crypto.compress(order_data))
    segments = [
        _b64(encrypted[i : i + _RAW_SEGMENT]) for i in range(0, len(encrypted), _RAW_SEGMENT)
    ]
    return UploadPayload(transaction_key, digest, signature_data, segments)


def build_btu_init(
    ctx: RequestContext,
    keyring: Keyring,
    service: Service,
    upload: UploadPayload,
    file_name: str | None = None,
    signature_flag: bool = True,
) -> bytes:
    """BTU initialisation: announce an upload with its signature and digest.

    signature_flag adds SignatureFlag, asking the bank to authorise the order with
    the attached electronic signature (BTUParamsType in ebics_orders_H005.xsd).
    """
    root, header, static, details = _secured_init(ctx, "BTU")
    params = _sub(details, _e("BTUOrderParams"))
    if file_name:
        params.set("fileName", file_name)
    _service(params, service)
    if signature_flag:
        _sub(params, _e("SignatureFlag"))
    body = _finish_init(root, header, static, keyring, num_segments=len(upload.segments))
    transfer = _sub(body, _e("DataTransfer"))
    info = _sub(transfer, _e("DataEncryptionInfo"), authenticate="true")
    _, bank_encryption = keyring.bank_certificates()
    _sub(
        info,
        _e("EncryptionPubKeyDigest"),
        _b64(crypto.certificate_digest(bank_encryption)),
        Version=crypto.ENCRYPTION,
        Algorithm=SHA256_URI,
    )
    encrypted_key = crypto.encrypt_transaction_key(
        keyring.bank_encryption_key(), upload.transaction_key
    )
    _sub(info, _e("TransactionKey"), _b64(encrypted_key))
    _sub(transfer, _e("SignatureData"), _b64(upload.signature_data), authenticate="true")
    _sub(transfer, _e("DataDigest"), _b64(upload.digest), SignatureVersion=crypto.SIGNATURE)
    xmlsig.sign(root, keyring.authentication_key)
    return _serialize(root)


def build_upload_transfer(
    ctx: RequestContext,
    keyring: Keyring,
    transaction_id: str,
    segment: int,
    last: bool,
    order_data_segment: str,
) -> bytes:
    """BTU transfer: send one base64 segment of the encrypted order data."""
    root, mutable = _transaction(ctx, transaction_id, "Transfer")
    _sub(mutable, _e("SegmentNumber"), str(segment), lastSegment="true" if last else "false")
    transfer = _sub(_sub(root, _e("body")), _e("DataTransfer"))
    _sub(transfer, _e("OrderData"), order_data_segment)
    xmlsig.sign(root, keyring.authentication_key)
    return _serialize(root)
