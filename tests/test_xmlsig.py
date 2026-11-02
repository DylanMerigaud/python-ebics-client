from __future__ import annotations

import base64
import hashlib

import pytest
from lxml import etree

from ebics_client import SignatureInvalid, xmlsig
from tests.conftest import pooled_key

H005 = "urn:org:ebics:H005"
DS = "http://www.w3.org/2000/09/xmldsig#"

DOC = (
    b'<ebicsRequest xmlns="urn:org:ebics:H005" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
    b' Version="H005" Revision="1">'
    b'<header authenticate="true"><static><HostID>HOST</HostID></static><mutable/></header>'
    b'<body><DataTransfer><SignatureData authenticate="true">QUJD</SignatureData>'
    b"<OrderData>ZZZ</OrderData></DataTransfer></body></ebicsRequest>"
)


def signed() -> etree._Element:
    root = etree.fromstring(DOC)
    xmlsig.sign(root, pooled_key(1))
    return root


def test_auth_signature_inserted_after_header() -> None:
    root = signed()
    names = [etree.QName(child).localname for child in root]
    assert names == ["header", "AuthSignature", "body"]
    info = root.find(f"{{{H005}}}AuthSignature/{{{DS}}}SignedInfo")
    assert info is not None
    reference = info.find(f"{{{DS}}}Reference")
    assert reference is not None
    assert reference.get("URI") == "#xpointer(//*[@authenticate='true'])"
    method = info.find(f"{{{DS}}}SignatureMethod")
    assert method is not None
    assert method.get("Algorithm") == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"


def test_digest_is_sha256_of_concatenated_c14n() -> None:
    root = signed()
    expected = hashlib.sha256(
        b"".join(
            etree.tostring(el, method="c14n")
            for el in root.xpath("//*[@authenticate='true']")
        )
    ).digest()
    value = root.findtext(f".//{{{DS}}}DigestValue")
    assert value is not None
    assert base64.b64decode(value) == expected


def test_signature_verifies_after_round_trip() -> None:
    xml = etree.tostring(signed())
    xmlsig.verify(etree.fromstring(xml), pooled_key(1).public_key())


def test_tampering_authenticated_element_breaks_signature() -> None:
    xml = etree.tostring(signed()).replace(b"<HostID>HOST</HostID>", b"<HostID>EVIL</HostID>")
    with pytest.raises(SignatureInvalid):
        xmlsig.verify(etree.fromstring(xml), pooled_key(1).public_key())


def test_tampering_body_authenticated_element_breaks_signature() -> None:
    xml = etree.tostring(signed()).replace(b">QUJD<", b">QUJE<")
    with pytest.raises(SignatureInvalid):
        xmlsig.verify(etree.fromstring(xml), pooled_key(1).public_key())


def test_unauthenticated_content_is_not_covered() -> None:
    xml = etree.tostring(signed()).replace(b">ZZZ<", b">YYY<")
    xmlsig.verify(etree.fromstring(xml), pooled_key(1).public_key())


def test_wrong_key_refused() -> None:
    with pytest.raises(SignatureInvalid):
        xmlsig.verify(signed(), pooled_key(3).public_key())


def test_missing_signature_refused() -> None:
    with pytest.raises(SignatureInvalid):
        xmlsig.verify(etree.fromstring(DOC), pooled_key(1).public_key())


def test_signed_info_tampering_refused() -> None:
    xml = etree.tostring(signed()).replace(b"rsa-sha256", b"rsa-sha1")
    with pytest.raises(SignatureInvalid):
        xmlsig.verify(etree.fromstring(xml), pooled_key(1).public_key())
