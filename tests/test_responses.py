from __future__ import annotations

import base64
import zlib

import pytest
from cryptography.hazmat.primitives import serialization

from ebics_client import (
    EbicsBusinessError,
    EbicsError,
    EbicsTechnicalError,
    NoDownloadData,
    crypto,
    responses,
)
from tests.conftest import assert_valid, pooled_key

HEADER = '<ebicsResponse xmlns="urn:org:ebics:H005" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Version="H005" Revision="1">'


def response(static: str, mutable: str, body: str) -> bytes:
    return (
        f'{HEADER}<header authenticate="true"><static>{static}</static>'
        f"<mutable>{mutable}</mutable></header>"
        "<AuthSignature><ds:SignedInfo>"
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        '<ds:Reference URI="#xpointer(//*[@authenticate=\'true\'])">'
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        "<ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        "<ds:SignatureValue>AAAA</ds:SignatureValue></AuthSignature>"
        f"<body>{body}</body></ebicsResponse>"
    ).encode()


def test_parse_download_init() -> None:
    xml = response(
        "<TransactionID>0123456789ABCDEF0123456789ABCDEF</TransactionID><NumSegments>3</NumSegments>",
        '<TransactionPhase>Initialisation</TransactionPhase><SegmentNumber lastSegment="false">1</SegmentNumber>'
        "<ReturnCode>000000</ReturnCode><ReportText>[EBICS_OK] OK</ReportText>",
        '<DataTransfer><DataEncryptionInfo authenticate="true">'
        '<EncryptionPubKeyDigest Version="E002" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256">AAAA</EncryptionPubKeyDigest>'
        "<TransactionKey>QUJD</TransactionKey></DataEncryptionInfo>"
        "<OrderData>RERE</OrderData></DataTransfer>"
        '<ReturnCode authenticate="true">000000</ReturnCode>',
    )
    assert_valid(xml)
    parsed = responses.parse_response(xml)
    assert parsed.kind == "ebicsResponse"
    assert parsed.transaction_id == "0123456789ABCDEF0123456789ABCDEF"
    assert parsed.num_segments == 3
    assert parsed.segment_number == 1
    assert parsed.last_segment is False
    assert parsed.phase == "Initialisation"
    assert parsed.technical_code == "000000"
    assert parsed.business_code == "000000"
    assert parsed.report_text == "[EBICS_OK] OK"
    assert parsed.transaction_key == b"ABC"
    assert parsed.order_data == "RERE"
    parsed.raise_for_codes()


def test_no_download_data() -> None:
    xml = response(
        "",
        "<TransactionPhase>Initialisation</TransactionPhase><ReturnCode>000000</ReturnCode>"
        "<ReportText>[EBICS_OK] OK</ReportText>",
        '<ReturnCode authenticate="true">090005</ReturnCode>',
    )
    assert_valid(xml)
    with pytest.raises(NoDownloadData) as info:
        responses.parse_response(xml).raise_for_codes()
    assert info.value.code == "090005"
    assert isinstance(info.value, EbicsBusinessError)


def test_technical_error() -> None:
    xml = response(
        "",
        "<TransactionPhase>Initialisation</TransactionPhase><ReturnCode>091002</ReturnCode>"
        "<ReportText>[EBICS_INVALID_USER_OR_USER_STATE] user state</ReportText>",
        '<ReturnCode authenticate="true">000000</ReturnCode>',
    )
    with pytest.raises(EbicsTechnicalError) as info:
        responses.parse_response(xml).raise_for_codes()
    assert info.value.code == "091002"
    assert "user state" in str(info.value)


def test_business_error() -> None:
    xml = response(
        "",
        "<TransactionPhase>Initialisation</TransactionPhase><ReturnCode>000000</ReturnCode>"
        "<ReportText>[EBICS_OK] OK</ReportText>",
        '<ReturnCode authenticate="true">091301</ReturnCode>',
    )
    with pytest.raises(EbicsBusinessError) as info:
        responses.parse_response(xml).raise_for_codes()
    assert info.value.code == "091301"
    assert "SIGNATURE_VERIFICATION_FAILED" in str(info.value)


def test_receipt_done_is_not_an_error() -> None:
    xml = response(
        "<TransactionID>0123456789ABCDEF0123456789ABCDEF</TransactionID>",
        "<TransactionPhase>Receipt</TransactionPhase><ReturnCode>011000</ReturnCode>"
        "<ReportText>[EBICS_DOWNLOAD_POSTPROCESS_DONE] done</ReportText>",
        '<ReturnCode authenticate="true">000000</ReturnCode>',
    )
    responses.parse_response(xml).raise_for_codes()


@pytest.mark.parametrize("body", ["", "<ReturnCode authenticate=\"true\"></ReturnCode>"])
def test_missing_business_return_code_is_an_error(body: str) -> None:
    xml = response(
        "<TransactionID>0123456789ABCDEF0123456789ABCDEF</TransactionID>",
        "<TransactionPhase>Transfer</TransactionPhase><ReturnCode>000000</ReturnCode>"
        "<ReportText>[EBICS_OK] OK</ReportText>",
        body,
    )
    parsed = responses.parse_response(xml)
    with pytest.raises(EbicsError, match="no business ReturnCode"):
        parsed.raise_for_codes()


def test_missing_business_code_does_not_hide_a_technical_error() -> None:
    xml = response(
        "",
        "<TransactionPhase>Initialisation</TransactionPhase><ReturnCode>091002</ReturnCode>"
        "<ReportText>[EBICS_INVALID_USER_OR_USER_STATE] bad</ReportText>",
        "",
    )
    with pytest.raises(EbicsTechnicalError) as info:
        responses.parse_response(xml).raise_for_codes()
    assert info.value.code == "091002"


def test_keymanagement_response() -> None:
    xml = (
        b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005" Version="H005" Revision="1">'
        b'<header authenticate="true"><static/><mutable><OrderID>A001</OrderID>'
        b"<ReturnCode>000000</ReturnCode><ReportText>[EBICS_OK] OK</ReportText></mutable></header>"
        b'<body><ReturnCode authenticate="true">000000</ReturnCode></body>'
        b"</ebicsKeyManagementResponse>"
    )
    assert_valid(xml)
    parsed = responses.parse_response(xml)
    assert parsed.kind == "ebicsKeyManagementResponse"
    assert parsed.order_id == "A001"
    parsed.raise_for_codes()


def test_hev_response() -> None:
    xml = (
        b'<ebicsHEVResponse xmlns="http://www.ebics.org/H000">'
        b"<SystemReturnCode><ReturnCode>000000</ReturnCode><ReportText>[EBICS_OK]</ReportText>"
        b"</SystemReturnCode>"
        b'<VersionNumber ProtocolVersion="H004">02.50</VersionNumber>'
        b'<VersionNumber ProtocolVersion="H005">03.00</VersionNumber>'
        b"</ebicsHEVResponse>"
    )
    versions = responses.parse_hev(xml)
    assert versions == [
        responses.ProtocolVersion("H004", "02.50"),
        responses.ProtocolVersion("H005", "03.00"),
    ]


def test_hev_error() -> None:
    xml = (
        b'<ebicsHEVResponse xmlns="http://www.ebics.org/H000">'
        b"<SystemReturnCode><ReturnCode>091011</ReturnCode><ReportText>bad host</ReportText>"
        b"</SystemReturnCode></ebicsHEVResponse>"
    )
    with pytest.raises(EbicsTechnicalError):
        responses.parse_hev(xml)


def test_doctype_and_entities_refused() -> None:
    xml = (
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        b'<ebicsResponse xmlns="urn:org:ebics:H005">&e;</ebicsResponse>'
    )
    with pytest.raises(EbicsError):
        responses.parse_response(xml)
    with pytest.raises(EbicsError):
        responses.parse_response(b"not xml")


def test_unknown_root_refused() -> None:
    with pytest.raises(EbicsError):
        responses.parse_response(b'<foo xmlns="urn:org:ebics:H005"/>')


def test_decode_segments_handles_both_splits() -> None:
    data = bytes(range(256)) * 10
    whole = base64.b64encode(data).decode()
    # Split on raw bytes (each segment padded base64) and on base64 text.
    raw_split = [base64.b64encode(data[:100]).decode(), base64.b64encode(data[100:]).decode()]
    text_split = [whole[:400], whole[400:]]
    assert responses.decode_segments(raw_split) == data
    assert responses.decode_segments(text_split) == data
    assert responses.decode_segments([whole[:401], whole[401:]]) == data


def test_decrypt_order_data() -> None:
    key = pooled_key(2)
    encrypted_key, ciphertext = crypto.e002_encrypt(key.public_key(), zlib.compress(b"payload"))
    assert responses.decrypt_order_data(key, encrypted_key, ciphertext) == b"payload"


@pytest.mark.parametrize(
    "compressed",
    [zlib.compress(b"payload")[:-3], zlib.compress(b"payload") + b"tail"],
    ids=["truncated", "trailing"],
)
def test_decrypt_order_data_refuses_bad_zlib(compressed: bytes) -> None:
    key = pooled_key(2)
    encrypted_key, ciphertext = crypto.e002_encrypt(key.public_key(), compressed)
    with pytest.raises(EbicsError, match="could not be decrypted"):
        responses.decrypt_order_data(key, encrypted_key, ciphertext)


def test_parse_hpb_order_data() -> None:
    auth = crypto.generate_certificate(pooled_key(3), crypto.AUTHENTICATION, "BANK")
    enc = crypto.generate_certificate(pooled_key(4), crypto.ENCRYPTION, "BANK")

    def info(name: str, version_name: str, version: str, cert: object) -> str:
        der = cert.public_bytes(serialization.Encoding.DER)  # type: ignore[attr-defined]
        return (
            f"<{name}><ds:X509Data><ds:X509Certificate>{base64.b64encode(der).decode()}"
            f"</ds:X509Certificate></ds:X509Data><{version_name}>{version}</{version_name}></{name}>"
        )

    xml = (
        '<HPBResponseOrderData xmlns="urn:org:ebics:H005" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        + info("AuthenticationPubKeyInfo", "AuthenticationVersion", "X002", auth)
        + info("EncryptionPubKeyInfo", "EncryptionVersion", "E002", enc)
        + "<HostID>EBIXHOST</HostID></HPBResponseOrderData>"
    ).encode()
    assert_valid(xml, "ebics_orders_H005.xsd")
    parsed = responses.parse_hpb_order_data(xml)
    assert parsed.authentication == auth
    assert parsed.encryption == enc
    assert parsed.host_id == "EBIXHOST"
    bad = xml.replace(b">X002<", b">X001<")
    with pytest.raises(EbicsError):
        responses.parse_hpb_order_data(bad)
