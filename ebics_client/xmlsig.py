"""The X002 authentication signature (AuthSignature) of EBICS H005 messages."""

from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from . import crypto
from .errors import SignatureInvalid

__all__ = [
    "C14N",
    "DIGEST_METHOD",
    "DS_NS",
    "H005_NS",
    "REFERENCE_URI",
    "SIGNATURE_METHOD",
    "authenticated_digest",
    "sign",
    "verify",
]

H005_NS = "urn:org:ebics:H005"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
DIGEST_METHOD = "http://www.w3.org/2001/04/xmlenc#sha256"
REFERENCE_URI = "#xpointer(//*[@authenticate='true'])"


def _ds(name: str) -> str:
    return f"{{{DS_NS}}}{name}"


def _c14n(element: etree._Element) -> bytes:
    # Inclusive C14N 1.0 without comments; namespaces in scope are rendered on the apex.
    return etree.tostring(element, method="c14n", exclusive=False, with_comments=False)


def authenticated_digest(root: etree._Element) -> bytes:
    """SHA-256 over the concatenated C14N of every element with authenticate="true"."""
    digest = hashlib.sha256()
    for element in root.iter():
        # Document order, same set as the XPath //*[@authenticate='true'].
        if isinstance(element.tag, str) and element.get("authenticate") == "true":
            digest.update(_c14n(element))
    return digest.digest()


def sign(root: etree._Element, private_key: rsa.RSAPrivateKey) -> etree._Element:
    """Insert an AuthSignature right after the header, signed with the X002 key."""
    header = root.find(f"{{{H005_NS}}}header")
    if header is None:
        raise ValueError("the message has no header to sign")
    digest = authenticated_digest(root)

    signature = etree.Element(f"{{{H005_NS}}}AuthSignature")
    info = etree.SubElement(signature, _ds("SignedInfo"))
    etree.SubElement(info, _ds("CanonicalizationMethod"), Algorithm=C14N)
    etree.SubElement(info, _ds("SignatureMethod"), Algorithm=SIGNATURE_METHOD)
    reference = etree.SubElement(info, _ds("Reference"), URI=REFERENCE_URI)
    transforms = etree.SubElement(reference, _ds("Transforms"))
    etree.SubElement(transforms, _ds("Transform"), Algorithm=C14N)
    etree.SubElement(reference, _ds("DigestMethod"), Algorithm=DIGEST_METHOD)
    etree.SubElement(reference, _ds("DigestValue")).text = base64.b64encode(digest).decode()
    value = etree.SubElement(signature, _ds("SignatureValue"))
    header.addnext(signature)

    # SignedInfo is canonicalised in place so that inherited namespaces match what
    # the receiver computes on the serialised message.
    value.text = base64.b64encode(crypto.x002_sign(private_key, _c14n(info))).decode()
    return signature


def _only(parent: etree._Element, path: str) -> etree._Element:
    found = parent.findall(path)
    if len(found) != 1:
        raise SignatureInvalid(text=f"AuthSignature must hold exactly one {path}")
    return found[0]


def verify(root: etree._Element, public_key: rsa.RSAPublicKey) -> None:
    """Check the AuthSignature with the sender's X002 key, raising SignatureInvalid."""
    signature = _only(root, f"{{{H005_NS}}}AuthSignature")
    info = _only(signature, _ds("SignedInfo"))
    expected = {
        _ds("CanonicalizationMethod"): C14N,
        _ds("SignatureMethod"): SIGNATURE_METHOD,
        f"{_ds('Reference')}/{_ds('DigestMethod')}": DIGEST_METHOD,
    }
    for path, algorithm in expected.items():
        if _only(info, path).get("Algorithm") != algorithm:
            raise SignatureInvalid(text=f"unexpected algorithm in {path}")
    reference = _only(info, _ds("Reference"))
    if reference.get("URI") != REFERENCE_URI:
        raise SignatureInvalid(text="unexpected Reference URI in AuthSignature")
    for transform in reference.iter(_ds("Transform")):
        if transform.get("Algorithm") != C14N:
            raise SignatureInvalid(text="unexpected transform in AuthSignature")

    try:
        claimed = base64.b64decode(
            "".join((_only(reference, _ds("DigestValue")).text or "").split()), validate=True
        )
        signature_value = base64.b64decode(
            "".join((_only(signature, _ds("SignatureValue")).text or "").split()), validate=True
        )
    except ValueError as exc:
        raise SignatureInvalid(text="AuthSignature is not valid base64") from exc
    if not hmac.compare_digest(claimed, authenticated_digest(root)):
        raise SignatureInvalid(text="digest of the authenticated elements does not match")
    if not crypto.x002_verify(public_key, signature_value, _c14n(info)):
        raise SignatureInvalid(text="X002 authentication signature does not verify")
