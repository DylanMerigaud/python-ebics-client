from __future__ import annotations

import base64
import hashlib
import os
import re
import zlib
from datetime import date

import pytest
from lxml import etree

from ebics_client import (
    Bank,
    Keyring,
    KeyringError,
    Service,
    User,
    crypto,
    requests,
    xmlsig,
)
from tests.conftest import assert_valid, pooled_key

H005 = "urn:org:ebics:H005"
S002 = "http://www.ebics.org/S002"
DS = "http://www.w3.org/2000/09/xmldsig#"
NS = {"e": H005, "ds": DS, "s": S002}

BANK = Bank(host_id="EBIXHOST", url="https://bank.example/ebics")
USER = User(partner_id="PARTNER1", user_id="USER1")
CTX = requests.RequestContext.create(BANK, USER)


def keyring(with_bank: bool = True) -> Keyring:
    ring = Keyring.from_keys(USER, pooled_key(0), pooled_key(1), pooled_key(2), "CH")
    if with_bank:
        ring.set_bank_certificates(
            crypto.generate_certificate(pooled_key(3), crypto.AUTHENTICATION, "BANK"),
            crypto.generate_certificate(pooled_key(4), crypto.ENCRYPTION, "BANK"),
        )
    return ring


def text(xml: bytes, path: str) -> str:
    found = etree.fromstring(xml).xpath(path, namespaces=NS)
    assert found, path
    value = found[0]
    return value if isinstance(value, str) else (value.text or "")


def order_data(xml: bytes) -> bytes:
    return zlib.decompress(base64.b64decode(text(xml, "//e:OrderData")))


def test_hev_request() -> None:
    xml = requests.build_hev("EBIXHOST")
    root = etree.fromstring(xml)
    assert root.tag == "{http://www.ebics.org/H000}ebicsHEVRequest"
    assert root.findtext("{http://www.ebics.org/H000}HostID") == "EBIXHOST"


def test_ini_request_validates() -> None:
    ring = keyring(with_bank=False)
    xml = requests.build_ini(CTX, ring)
    assert_valid(xml)
    root = etree.fromstring(xml)
    assert root.tag == f"{{{H005}}}ebicsUnsecuredRequest"
    assert root.get("Version") == "H005" and root.get("Revision") == "1"
    assert text(xml, "//e:AdminOrderType") == "INI"
    data = order_data(xml)
    assert_valid(data, "ebics_signature_S002.xsd")
    doc = etree.fromstring(data)
    cert_b64 = doc.findtext(".//ds:X509Certificate", namespaces=NS)
    assert cert_b64 is not None
    assert base64.b64decode(cert_b64) == ring.signature_certificate.public_bytes(
        crypto.serialization.Encoding.DER
    )
    assert doc.findtext(".//s:SignatureVersion", namespaces=NS) == "A006"
    serial = doc.findtext(".//ds:X509SerialNumber", namespaces=NS)
    assert serial == str(ring.signature_certificate.serial_number)


def test_hia_request_validates() -> None:
    xml = requests.build_hia(CTX, keyring(with_bank=False))
    assert_valid(xml)
    assert text(xml, "//e:AdminOrderType") == "HIA"
    data = order_data(xml)
    assert_valid(data, "ebics_orders_H005.xsd")
    doc = etree.fromstring(data)
    assert doc.tag == f"{{{H005}}}HIARequestOrderData"
    assert doc.findtext(".//e:AuthenticationVersion", namespaces=NS) == "X002"
    assert doc.findtext(".//e:EncryptionVersion", namespaces=NS) == "E002"


def test_h3k_request_validates_and_is_signed() -> None:
    ring = keyring(with_bank=False)
    xml = requests.build_h3k(CTX, ring)
    assert_valid(xml)
    root = etree.fromstring(xml)
    assert root.tag == f"{{{H005}}}ebicsUnsignedRequest"
    data = order_data(xml)
    assert_valid(data, "ebics_orders_H005.xsd")
    assert etree.fromstring(data).tag == f"{{{H005}}}H3KRequestOrderData"
    sig_data = zlib.decompress(base64.b64decode(text(xml, "//e:SignatureData")))
    assert_valid(sig_data, "ebics_signature_S002.xsd")
    value = etree.fromstring(sig_data).findtext(".//s:SignatureValue", namespaces=NS)
    assert value is not None
    signed_bytes = crypto.normalize_order_data(data)
    assert crypto.a006_verify(ring.signature_key.public_key(), base64.b64decode(value), signed_bytes)
    # Not encrypted: there is no bank key yet when H3K is sent.


def test_hpb_request_validates_and_is_authenticated() -> None:
    ring = keyring(with_bank=False)
    xml = requests.build_hpb(CTX, ring)
    assert_valid(xml)
    root = etree.fromstring(xml)
    assert root.tag == f"{{{H005}}}ebicsNoPubKeyDigestsRequest"
    xmlsig.verify(root, ring.authentication_key.public_key())
    assert re.fullmatch(r"[0-9A-F]{32}", text(xml, "//e:Nonce"))
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", text(xml, "//e:Timestamp"))


def test_btd_request_validates_with_service_and_dates() -> None:
    ring = keyring()
    xml = requests.build_btd_init(
        CTX, ring, Service.CAMT_053_CH, start=date(2026, 10, 1), end=date(2026, 10, 31)
    )
    assert_valid(xml)
    xmlsig.verify(etree.fromstring(xml), ring.authentication_key.public_key())
    assert text(xml, "//e:AdminOrderType") == "BTD"
    service = etree.fromstring(xml).find(".//e:BTDOrderParams/e:Service", namespaces=NS)
    assert service is not None
    assert [etree.QName(c).localname for c in service] == [
        "ServiceName",
        "Scope",
        "Container",
        "MsgName",
    ]
    assert text(xml, "//e:MsgName/@version") == "08"
    assert text(xml, "//e:Container/@containerType") == "ZIP"
    assert text(xml, "//e:DateRange/e:Start") == "2026-10-01"
    digest = crypto.certificate_digest(ring.bank_authentication_certificate)  # type: ignore[arg-type]
    assert base64.b64decode(text(xml, "//e:BankPubKeyDigests/e:Authentication")) == digest
    assert text(xml, "//e:TransactionPhase") == "Initialisation"


def test_btd_full_service_element_order() -> None:
    service = Service(
        "STM", "camt.054", scope="DE", option="SCI", container="ZIP", msg_version="08",
        variant="001", format="XML",
    )
    xml = requests.build_btd_init(CTX, keyring(), service)
    assert_valid(xml)
    element = etree.fromstring(xml).find(".//e:Service", namespaces=NS)
    assert element is not None
    assert [etree.QName(c).localname for c in element] == [
        "ServiceName", "Scope", "ServiceOption", "Container", "MsgName",
    ]


def test_btd_needs_bank_keys() -> None:
    with pytest.raises(KeyringError):
        requests.build_btd_init(CTX, keyring(with_bank=False), Service.CAMT_053_CH)


def test_transfer_and_receipt_requests_validate() -> None:
    ring = keyring()
    tid = "0123456789ABCDEF0123456789ABCDEF"
    xml = requests.build_download_transfer(CTX, ring, tid, 2, last=False)
    assert_valid(xml)
    assert text(xml, "//e:SegmentNumber") == "2"
    assert text(xml, "//e:SegmentNumber/@lastSegment") == "false"
    receipt = requests.build_receipt(CTX, ring, tid, acknowledged=True)
    assert_valid(receipt)
    assert text(receipt, "//e:ReceiptCode") == "0"
    assert text(requests.build_receipt(CTX, ring, tid, acknowledged=False), "//e:ReceiptCode") == "1"
    xmlsig.verify(etree.fromstring(receipt), ring.authentication_key.public_key())


def test_btu_requests_validate_and_carry_signature() -> None:
    ring = keyring()
    document = b"<Document>\r\n<pain/>\n</Document>"
    upload = requests.prepare_upload(CTX, ring, document)
    xml = requests.build_btu_init(CTX, ring, Service.PAIN_001_CH, upload, file_name="pain.xml")
    assert_valid(xml)
    xmlsig.verify(etree.fromstring(xml), ring.authentication_key.public_key())
    assert text(xml, "//e:NumSegments") == "1"
    assert text(xml, "//e:BTUOrderParams/@fileName") == "pain.xml"
    normalized = b"<Document><pain/></Document>"
    assert base64.b64decode(text(xml, "//e:DataDigest")) == hashlib.sha256(normalized).digest()
    assert text(xml, "//e:DataDigest/@SignatureVersion") == "A006"

    # SignatureData decrypts with the bank's key (simulated here with the pooled key).
    encrypted_key = base64.b64decode(text(xml, "//e:TransactionKey"))
    transaction_key = crypto.decrypt_transaction_key(pooled_key(4), encrypted_key)
    sig_data = zlib.decompress(
        crypto.aes_decrypt(transaction_key, base64.b64decode(text(xml, "//e:SignatureData")))
    )
    assert_valid(sig_data, "ebics_signature_S002.xsd")
    value = etree.fromstring(sig_data).findtext(".//s:SignatureValue", namespaces=NS)
    assert value is not None
    assert crypto.a006_verify(ring.signature_key.public_key(), base64.b64decode(value), normalized)

    transfer = requests.build_upload_transfer(CTX, ring, "AB" * 16, 1, True, upload.segments[0])
    assert_valid(transfer)
    sent = zlib.decompress(
        crypto.aes_decrypt(transaction_key, base64.b64decode(text(transfer, "//e:OrderData")))
    )
    assert sent == document  # transmitted unchanged, only the hash input is normalized


def test_upload_segments_are_at_most_one_megabyte() -> None:
    ring = keyring()
    payload = os.urandom(2_200_000)  # incompressible: 2.2 MB of ciphertext, 3 segments
    upload = requests.prepare_upload(CTX, ring, payload)
    assert len(upload.segments) == 3
    assert all(len(s) <= 1024 * 1024 for s in upload.segments)
    joined = b"".join(base64.b64decode(s) for s in upload.segments)
    assert zlib.decompress(crypto.aes_decrypt(upload.transaction_key, joined)) == payload


def test_signature_flag_and_system_id() -> None:
    ctx = requests.RequestContext.create(BANK, User("PARTNER1", "USER1", system_id="SYS1"))
    ring = keyring()
    upload = requests.prepare_upload(ctx, ring, b"<x/>")
    xml = requests.build_btu_init(ctx, ring, Service.PAIN_001_DE, upload)
    assert_valid(xml)
    assert etree.fromstring(xml).find(".//e:SignatureFlag", namespaces=NS) is not None
    assert text(xml, "//e:SystemID") == "SYS1"
    xml = requests.build_btu_init(ctx, ring, Service.PAIN_001_DE, upload, signature_flag=False)
    assert_valid(xml)
    assert etree.fromstring(xml).find(".//e:SignatureFlag", namespaces=NS) is None
