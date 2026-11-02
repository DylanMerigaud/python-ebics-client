"""FakeBank: an in-process EBICS 3.0 (H005) bank for tests, examples and offline demos.

FakeBank is a transport: pass it as EbicsClient(..., transport=bank). It answers
HEV, INI, HIA, H3K, HPB, BTD (files registered with register_download) and BTU
(uploads land in bank.uploads after the A006 signature was verified).

Its checks of the client's signatures and digests are written here from the
specification, on top of `cryptography` and lxml directly, and do not reuse the
client's xmlsig or crypto helpers, so tests against it are not circular.
"""

from __future__ import annotations

import base64
import hashlib
import io
import secrets
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from importlib import resources
from typing import TYPE_CHECKING, Callable, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
from lxml import etree

from .errors import SignatureInvalid
from .keyring import Bank
from .service import Service

if TYPE_CHECKING:
    from .client import EbicsClient

__all__ = ["FakeBank", "ReceivedUpload", "Subscriber", "sample_camt053"]

H005 = "urn:org:ebics:H005"
H000 = "http://www.ebics.org/H000"
DS = "http://www.w3.org/2000/09/xmldsig#"
S002 = "http://www.ebics.org/S002"
_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_NS = {"e": H005, "ds": DS, "s": S002}


def sample_camt053() -> bytes:
    """A small, realistic Swiss camt.053.001.08 statement shipped with the package."""
    return (resources.files("ebics_client") / "samples" / "camt053_ch.xml").read_bytes()


@dataclass
class Subscriber:
    """What the bank knows about one user."""

    partner_id: str
    user_id: str
    signature_certificate: x509.Certificate | None = None
    authentication_certificate: x509.Certificate | None = None
    encryption_certificate: x509.Certificate | None = None

    @property
    def ready(self) -> bool:
        """True once all three certificates arrived (the bank activates the user)."""
        return None not in (
            self.signature_certificate,
            self.authentication_certificate,
            self.encryption_certificate,
        )


@dataclass
class ReceivedUpload:
    """A file the bank accepted through BTU."""

    order_id: str
    service: Service
    data: bytes
    file_name: str | None
    partner_id: str
    user_id: str
    signature_verified: bool


@dataclass
class _File:
    data: bytes
    segment_size: int | None
    raw: bool


@dataclass
class _Transaction:
    kind: str
    subscriber: Subscriber
    order_id: str
    segments: list[str] = field(default_factory=list)
    service: Service | None = None
    files: list[_File] = field(default_factory=list)
    transaction_key: bytes = b""
    signature_data: bytes = b""
    data_digest: bytes = b""
    file_name: str | None = None
    expected_segments: int = 0


class _Refusal(Exception):
    def __init__(self, technical: str = "000000", business: str = "000000", text: str = "") -> None:
        super().__init__(text)
        self.technical = technical
        self.business = business
        self.text = text


# Independent primitives (spec level) -----------------------------------------


def _q(name: str, ns: str = H005) -> str:
    return f"{{{ns}}}{name}"


def _c14n(element: etree._Element) -> bytes:
    return etree.tostring(element, method="c14n")


def _auth_digest(root: etree._Element) -> bytes:
    nodes = root.xpath("//*[@authenticate='true']")
    return hashlib.sha256(b"".join(_c14n(n) for n in cast("list[etree._Element]", nodes))).digest()


def _pad(data: bytes) -> bytes:
    count = 16 - len(data) % 16
    return data + bytes(count - 1) + bytes([count])


def _aes(key: bytes, data: bytes, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16)))
    if encrypt:
        enc = cipher.encryptor()
        return enc.update(_pad(data)) + enc.finalize()
    dec = cipher.decryptor()
    plain = dec.update(data) + dec.finalize()
    return plain[: -plain[-1]]


def _hash_input(order_data: bytes) -> bytes:
    for char in (b"\r", b"\n", b"\x1a"):
        order_data = order_data.replace(char, b"")
    return order_data


def _a006_ok(certificate: x509.Certificate, signature: bytes, order_data: bytes) -> bool:
    key = cast(rsa.RSAPublicKey, certificate.public_key())
    hashed = hashlib.sha256(_hash_input(order_data)).digest()
    try:
        key.verify(
            signature,
            hashed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def _cert_digest(certificate: x509.Certificate) -> bytes:
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).digest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _bank_certificate(key: rsa.RSAPrivateKey, host_id: str, usage: str) -> x509.Certificate:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FakeBank"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, usage),
            x509.NameAttribute(NameOID.COMMON_NAME, host_id),
        ]
    )
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )


def _certificate_in(element: etree._Element | None) -> x509.Certificate:
    if element is None:
        raise _Refusal("091010", text="missing certificate")
    der = element.findtext("ds:X509Data/ds:X509Certificate", namespaces=_NS)
    if not der:
        raise _Refusal("091010", text="missing certificate")
    return x509.load_der_x509_certificate(base64.b64decode(der))


def _need(element: etree._Element | None) -> etree._Element:
    if element is None:
        raise _Refusal("091010", text="[EBICS_INVALID_XML] element missing")
    return element


def _parse(data: bytes) -> etree._Element:
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    return etree.fromstring(data, parser)


class FakeBank:
    """An in-process EBICS H005 bank. Call it like a transport: bank(url, body)."""

    def __init__(
        self,
        host_id: str = "FAKEBANK",
        url: str = "https://fakebank.example/ebicsweb",
        authentication_key: rsa.RSAPrivateKey | None = None,
        encryption_key: rsa.RSAPrivateKey | None = None,
    ) -> None:
        """Create a bank; its X002 and E002 keys are generated unless given."""
        self.host_id = host_id
        self.url = url
        self.subscribers: dict[tuple[str, str], Subscriber] = {}
        self.uploads: list[ReceivedUpload] = []
        self.last_date_range: tuple[date, date] | None = None
        #: Corrupt the SignatureValue of every ebicsResponse (to test the client).
        self.tamper_signatures = False
        #: Change an authenticated element after signing (to test the client).
        self.tamper_content = False
        self._downloads: dict[Service, list[_File]] = {}
        self._transactions: dict[str, _Transaction] = {}
        self._nonces: set[str] = set()
        self._order_counter = 0
        self.rotate_keys(authentication_key, encryption_key)

    # Configuration ------------------------------------------------------------

    @property
    def bank(self) -> Bank:
        """The Bank (host id and URL) to give to EbicsClient."""
        return Bank(host_id=self.host_id, url=self.url)

    def rotate_keys(
        self,
        authentication_key: rsa.RSAPrivateKey | None = None,
        encryption_key: rsa.RSAPrivateKey | None = None,
    ) -> None:
        """Install new bank keys (generated when not given) and certificates."""
        self.authentication_key = authentication_key or rsa.generate_private_key(65537, 2048)
        self.encryption_key = encryption_key or rsa.generate_private_key(65537, 2048)
        self.authentication_certificate = _bank_certificate(
            self.authentication_key, self.host_id, "X002"
        )
        self.encryption_certificate = _bank_certificate(self.encryption_key, self.host_id, "E002")

    def key_hashes(self) -> dict[str, str]:
        """The hashes the bank prints in its letter, formatted like letter.format_hash."""

        def fmt(digest: bytes) -> str:
            text = digest.hex().upper()
            return " ".join(text[i : i + 4] for i in range(0, len(text), 4))

        return {
            "X002": fmt(_cert_digest(self.authentication_certificate)),
            "E002": fmt(_cert_digest(self.encryption_certificate)),
        }

    def register_download(
        self, service: Service, data: bytes, segment_size: int | None = None, raw: bool = False
    ) -> None:
        """Make data available to the next BTD for service.

        segment_size (bytes of encrypted data per segment) lets a test force several
        segments. Files of a ZIP service are zipped together unless raw is True.
        """
        self._downloads.setdefault(service, []).append(_File(data, segment_size, raw))

    def pending(self, service: Service) -> int:
        """Number of files still waiting for service."""
        return len(self._downloads.get(service, []))

    def subscriber(self, partner_id: str, user_id: str) -> Subscriber:
        """The bank's record of a user (created on first contact)."""
        key = (partner_id, user_id)
        if key not in self.subscribers:
            self.subscribers[key] = Subscriber(partner_id, user_id)
        return self.subscribers[key]

    def onboard(self, client: EbicsClient) -> None:
        """Run INI, HIA and HPB for client and mark the bank keys verified.

        The verification compares the HPB hashes with this bank's letter, as a
        real onboarding does with the letter the bank sends.
        """
        client.ini()
        client.hia()
        hashes = client.hpb()
        if hashes != self.key_hashes():
            raise SignatureInvalid(text="the HPB hashes differ from the bank's letter")
        client.keyring.bank_keys_verified = True

    # Transport ----------------------------------------------------------------

    def __call__(self, url: str, body: bytes) -> bytes:
        """Answer one EBICS request."""
        root = _parse(body)
        tag = etree.QName(root)
        if tag.namespace == H000 and tag.localname == "ebicsHEVRequest":
            return self._hev()
        if tag.namespace != H005:
            raise ValueError(f"FakeBank does not understand {tag.text}")
        handlers: dict[str, Callable[[etree._Element], bytes]] = {
            "ebicsUnsecuredRequest": self._unsecured,
            "ebicsUnsignedRequest": self._unsigned,
            "ebicsNoPubKeyDigestsRequest": self._hpb,
            "ebicsRequest": self._request,
        }
        if tag.localname not in handlers:
            raise ValueError(f"FakeBank does not understand {tag.localname}")
        return handlers[tag.localname](root)

    # HEV and key management ---------------------------------------------------

    def _hev(self) -> bytes:
        root = etree.Element(
            _q("ebicsHEVResponse", H000), nsmap=cast("dict[str, str]", {None: H000})
        )
        code = etree.SubElement(root, _q("SystemReturnCode", H000))
        etree.SubElement(code, _q("ReturnCode", H000)).text = "000000"
        etree.SubElement(code, _q("ReportText", H000)).text = "[EBICS_OK] OK"
        version = etree.SubElement(root, _q("VersionNumber", H000), ProtocolVersion="H005")
        version.text = "03.00"
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8")

    def _static_subscriber(self, root: etree._Element) -> Subscriber:
        static = root.find("e:header/e:static", _NS)
        if static is None:
            raise _Refusal("091010", text="no static header")
        if static.findtext("e:HostID", namespaces=_NS) != self.host_id:
            raise _Refusal("091011", text="unknown host")
        partner = static.findtext("e:PartnerID", namespaces=_NS) or ""
        user = static.findtext("e:UserID", namespaces=_NS) or ""
        return self.subscriber(partner, user)

    def _order_data(self, root: etree._Element) -> etree._Element:
        text = root.findtext("e:body/e:DataTransfer/e:OrderData", namespaces=_NS) or ""
        return _parse(zlib.decompress(base64.b64decode(text)))

    def _unsecured(self, root: etree._Element) -> bytes:
        try:
            subscriber = self._static_subscriber(root)
            order_type = root.findtext(
                "e:header/e:static/e:OrderDetails/e:AdminOrderType", namespaces=_NS
            )
            data = self._order_data(root)
            if order_type == "INI":
                info = data.find("s:SignaturePubKeyInfo", _NS)
                subscriber.signature_certificate = _certificate_in(info)
            elif order_type == "HIA":
                auth = data.find("e:AuthenticationPubKeyInfo", _NS)
                enc = data.find("e:EncryptionPubKeyInfo", _NS)
                subscriber.authentication_certificate = _certificate_in(auth)
                subscriber.encryption_certificate = _certificate_in(enc)
            else:
                raise _Refusal("091005", text="unsupported order type")
        except _Refusal as refusal:
            return self._key_response(refusal.technical, refusal.business, refusal.text)
        return self._key_response(order_id=self._next_order_id())

    def _unsigned(self, root: etree._Element) -> bytes:
        try:
            subscriber = self._static_subscriber(root)
            order_type = root.findtext(
                "e:header/e:static/e:OrderDetails/e:AdminOrderType", namespaces=_NS
            )
            if order_type != "H3K":
                raise _Refusal("091005", text="unsupported order type")
            transfer = _need(root.find("e:body/e:DataTransfer", _NS))
            order_bytes = zlib.decompress(
                base64.b64decode(transfer.findtext("e:OrderData", namespaces=_NS) or "")
            )
            data = _parse(order_bytes)
            signature_xml = _parse(
                zlib.decompress(
                    base64.b64decode(transfer.findtext("e:SignatureData", namespaces=_NS) or "")
                )
            )
            signature_certificate = _certificate_in(data.find("e:SignatureCertificateInfo", _NS))
            value = (
                signature_xml.findtext("s:OrderSignatureData/s:SignatureValue", namespaces=_NS)
                or ""
            )
            if not _a006_ok(signature_certificate, base64.b64decode(value), order_bytes):
                raise _Refusal(business="091301", text="H3K signature does not verify")
            subscriber.signature_certificate = signature_certificate
            subscriber.authentication_certificate = _certificate_in(
                data.find("e:AuthenticationCertificateInfo", _NS)
            )
            subscriber.encryption_certificate = _certificate_in(
                data.find("e:EncryptionCertificateInfo", _NS)
            )
        except _Refusal as refusal:
            return self._key_response(refusal.technical, refusal.business, refusal.text)
        return self._key_response(order_id=self._next_order_id())

    def _hpb(self, root: etree._Element) -> bytes:
        try:
            subscriber = self._static_subscriber(root)
            if not subscriber.ready or subscriber.encryption_certificate is None:
                raise _Refusal("091002", text="user not initialised")
            self._check_auth(root, subscriber)
            self._check_nonce(root)
        except _Refusal as refusal:
            return self._key_response(refusal.technical, refusal.business, refusal.text)

        order = etree.Element(
            _q("HPBResponseOrderData"), nsmap=cast("dict[str, str]", {None: H005, "ds": DS})
        )
        for name, version_tag, version, certificate in (
            (
                "AuthenticationPubKeyInfo",
                "AuthenticationVersion",
                "X002",
                self.authentication_certificate,
            ),
            ("EncryptionPubKeyInfo", "EncryptionVersion", "E002", self.encryption_certificate),
        ):
            info = etree.SubElement(order, _q(name))
            x509_data = etree.SubElement(info, _q("X509Data", DS))
            der = certificate.public_bytes(serialization.Encoding.DER)
            etree.SubElement(x509_data, _q("X509Certificate", DS)).text = _b64(der)
            etree.SubElement(info, _q(version_tag)).text = version
        etree.SubElement(order, _q("HostID")).text = self.host_id
        payload = zlib.compress(etree.tostring(order, xml_declaration=True, encoding="UTF-8"))
        key = secrets.token_bytes(16)
        return self._key_response(
            encrypted=(subscriber.encryption_certificate, key, _aes(key, payload, encrypt=True))
        )

    def _key_response(
        self,
        technical: str = "000000",
        business: str = "000000",
        text: str = "",
        order_id: str | None = None,
        encrypted: tuple[x509.Certificate, bytes, bytes] | None = None,
    ) -> bytes:
        root = etree.Element(
            _q("ebicsKeyManagementResponse"),
            nsmap=cast("dict[str, str]", {None: H005, "ds": DS}),
            Version="H005",
            Revision="1",
        )
        header = etree.SubElement(root, _q("header"), authenticate="true")
        etree.SubElement(header, _q("static"))
        mutable = etree.SubElement(header, _q("mutable"))
        if order_id:
            etree.SubElement(mutable, _q("OrderID")).text = order_id
        etree.SubElement(mutable, _q("ReturnCode")).text = technical
        etree.SubElement(mutable, _q("ReportText")).text = text or "[EBICS_OK] OK"
        body = etree.SubElement(root, _q("body"))
        if encrypted is not None:
            self._data_transfer(body, *encrypted)
        etree.SubElement(body, _q("ReturnCode"), authenticate="true").text = business
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8")

    def _data_transfer(
        self,
        parent: etree._Element,
        certificate: x509.Certificate | None,
        key: bytes | None,
        segment: bytes | str,
    ) -> None:
        transfer = etree.SubElement(parent, _q("DataTransfer"))
        if certificate is not None and key is not None:
            info = etree.SubElement(transfer, _q("DataEncryptionInfo"), authenticate="true")
            digest = etree.SubElement(
                info, _q("EncryptionPubKeyDigest"), Version="E002", Algorithm=_SHA256
            )
            digest.text = _b64(_cert_digest(certificate))
            public = cast(rsa.RSAPublicKey, certificate.public_key())
            etree.SubElement(info, _q("TransactionKey")).text = _b64(
                public.encrypt(key, padding.PKCS1v15())
            )
        text = segment if isinstance(segment, str) else _b64(segment)
        etree.SubElement(transfer, _q("OrderData")).text = text

    # Authentication -----------------------------------------------------------

    def _check_auth(self, root: etree._Element, subscriber: Subscriber) -> None:
        certificate = subscriber.authentication_certificate
        if certificate is None:
            raise _Refusal("091002", text="user not initialised")
        info = root.find("e:AuthSignature/ds:SignedInfo", _NS)
        if info is None:
            raise _Refusal("061001", text="no AuthSignature")
        claimed = base64.b64decode(
            info.findtext("ds:Reference/ds:DigestValue", namespaces=_NS) or ""
        )
        value = base64.b64decode(
            root.findtext("e:AuthSignature/ds:SignatureValue", namespaces=_NS) or ""
        )
        if claimed != _auth_digest(root):
            raise _Refusal("061001", text="digest mismatch")
        key = cast(rsa.RSAPublicKey, certificate.public_key())
        try:
            key.verify(value, _c14n(info), padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as exc:
            raise _Refusal("061001", text="authentication signature invalid") from exc

    def _check_nonce(self, root: etree._Element) -> None:
        nonce = root.findtext("e:header/e:static/e:Nonce", namespaces=_NS) or ""
        if nonce in self._nonces:
            raise _Refusal("091103", text="message replay")
        self._nonces.add(nonce)

    def _check_bank_digests(self, root: etree._Element) -> None:
        digests = root.find("e:header/e:static/e:BankPubKeyDigests", _NS)
        if digests is None:
            raise _Refusal("091010", text="no bank key digests")
        auth = base64.b64decode(digests.findtext("e:Authentication", namespaces=_NS) or "")
        enc = base64.b64decode(digests.findtext("e:Encryption", namespaces=_NS) or "")
        if auth != _cert_digest(self.authentication_certificate) or enc != _cert_digest(
            self.encryption_certificate
        ):
            raise _Refusal("091008", text="bank key digests outdated")

    # ebicsRequest ---------------------------------------------------------------

    def _request(self, root: etree._Element) -> bytes:
        transaction_id = root.findtext("e:header/e:static/e:TransactionID", namespaces=_NS)
        phase = root.findtext("e:header/e:mutable/e:TransactionPhase", namespaces=_NS) or ""
        transaction: _Transaction | None = None
        try:
            if transaction_id:
                transaction = self._transactions.get(transaction_id)
                if transaction is None:
                    raise _Refusal("091101", text="unknown transaction")
                self._check_auth(root, transaction.subscriber)
                if phase == "Receipt":
                    return self._receipt(root, transaction_id, transaction)
                if transaction.kind == "BTD":
                    return self._download_segment(root, transaction_id, transaction)
                return self._upload_segment(root, transaction_id, transaction)
            subscriber = self._static_subscriber(root)
            if not subscriber.ready:
                raise _Refusal("091002", text="user not initialised")
            self._check_auth(root, subscriber)
            self._check_nonce(root)
            self._check_bank_digests(root)
            order_type = root.findtext(
                "e:header/e:static/e:OrderDetails/e:AdminOrderType", namespaces=_NS
            )
            if order_type == "BTD":
                return self._download_init(root, subscriber)
            if order_type == "BTU":
                return self._upload_init(root, subscriber)
            raise _Refusal("091005", text="unsupported order type")
        except _Refusal as refusal:
            return self._response(
                phase or "Initialisation",
                technical=refusal.technical,
                business=refusal.business,
                text=refusal.text,
                transaction_id=transaction_id if transaction else None,
            )

    def _service(self, params: etree._Element) -> Service:
        element = params.find("e:Service", _NS)
        if element is None:
            raise _Refusal("091112", text="no Service")
        container = element.find("e:Container", _NS)
        msg = _need(element.find("e:MsgName", _NS))
        return Service(
            name=element.findtext("e:ServiceName", namespaces=_NS) or "",
            msg_name=msg.text or "",
            scope=element.findtext("e:Scope", namespaces=_NS),
            option=element.findtext("e:ServiceOption", namespaces=_NS),
            container=container.get("containerType") if container is not None else None,
            msg_version=msg.get("version"),
            variant=msg.get("variant"),
            format=msg.get("format"),
        )

    def _download_init(self, root: etree._Element, subscriber: Subscriber) -> bytes:
        params = _need(root.find("e:header/e:static/e:OrderDetails/e:BTDOrderParams", _NS))
        service = self._service(params)
        start = params.findtext("e:DateRange/e:Start", namespaces=_NS)
        end = params.findtext("e:DateRange/e:End", namespaces=_NS)
        if start and end:
            self.last_date_range = (date.fromisoformat(start), date.fromisoformat(end))
        files = self._downloads.get(service, [])
        if not files:
            raise _Refusal(business="090005", text="[EBICS_OK] No download data available")
        if service.container == "ZIP" and not files[0].raw:
            chosen = list(files)
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                for index, item in enumerate(chosen, start=1):
                    archive.writestr(f"{service.msg_name}_{index:03d}.xml", item.data)
            payload = buffer.getvalue()
        else:
            chosen = [files[0]]
            payload = files[0].data
        key = secrets.token_bytes(16)
        encrypted = _aes(key, zlib.compress(payload), encrypt=True)
        size = chosen[0].segment_size or 786432
        segments = [_b64(encrypted[i : i + size]) for i in range(0, len(encrypted), size)]
        transaction_id = secrets.token_hex(16).upper()
        self._transactions[transaction_id] = _Transaction(
            "BTD",
            subscriber,
            self._next_order_id(),
            segments=segments,
            service=service,
            files=chosen,
        )
        return self._response(
            "Initialisation",
            transaction_id=transaction_id,
            num_segments=len(segments),
            segment=(1, len(segments) == 1),
            data=(subscriber.encryption_certificate, key, segments[0]),
        )

    def _download_segment(
        self, root: etree._Element, transaction_id: str, transaction: _Transaction
    ) -> bytes:
        number = int(root.findtext("e:header/e:mutable/e:SegmentNumber", namespaces=_NS) or "0")
        if not 1 <= number <= len(transaction.segments):
            raise _Refusal("091104", text="segment number exceeded")
        return self._response(
            "Transfer",
            transaction_id=transaction_id,
            segment=(number, number == len(transaction.segments)),
            data=(None, None, transaction.segments[number - 1]),
        )

    def _receipt(
        self, root: etree._Element, transaction_id: str, transaction: _Transaction
    ) -> bytes:
        code = root.findtext("e:body/e:TransferReceipt/e:ReceiptCode", namespaces=_NS)
        del self._transactions[transaction_id]
        if code == "0" and transaction.service is not None:
            remaining = self._downloads.get(transaction.service, [])
            for item in transaction.files:
                remaining.remove(item)
            return self._response(
                "Receipt",
                technical="011000",
                transaction_id=transaction_id,
                text="[EBICS_DOWNLOAD_POSTPROCESS_DONE] Positive acknowledgement received",
            )
        return self._response(
            "Receipt",
            technical="011001",
            transaction_id=transaction_id,
            text="[EBICS_DOWNLOAD_POSTPROCESS_SKIPPED] Negative acknowledgement received",
        )

    def _upload_init(self, root: etree._Element, subscriber: Subscriber) -> bytes:
        params = root.find("e:header/e:static/e:OrderDetails/e:BTUOrderParams", _NS)
        transfer = _need(root.find("e:body/e:DataTransfer", _NS))
        params = _need(params)
        service = self._service(params)
        digest = base64.b64decode(
            transfer.findtext("e:DataEncryptionInfo/e:EncryptionPubKeyDigest", namespaces=_NS) or ""
        )
        if digest != _cert_digest(self.encryption_certificate):
            raise _Refusal("091008", text="encrypted for an outdated bank key")
        wrapped = base64.b64decode(
            transfer.findtext("e:DataEncryptionInfo/e:TransactionKey", namespaces=_NS) or ""
        )
        key = self.encryption_key.decrypt(wrapped, padding.PKCS1v15())
        transaction_id = secrets.token_hex(16).upper()
        transaction = _Transaction(
            "BTU",
            subscriber,
            self._next_order_id(),
            service=service,
            transaction_key=key,
            signature_data=base64.b64decode(
                transfer.findtext("e:SignatureData", namespaces=_NS) or ""
            ),
            data_digest=base64.b64decode(transfer.findtext("e:DataDigest", namespaces=_NS) or ""),
            file_name=params.get("fileName"),
            expected_segments=int(
                root.findtext("e:header/e:static/e:NumSegments", namespaces=_NS) or "0"
            ),
        )
        self._transactions[transaction_id] = transaction
        return self._response(
            "Initialisation", transaction_id=transaction_id, order_id=transaction.order_id
        )

    def _upload_segment(
        self, root: etree._Element, transaction_id: str, transaction: _Transaction
    ) -> bytes:
        segment = _need(root.find("e:header/e:mutable/e:SegmentNumber", _NS))
        number = int(segment.text or "0")
        if number != len(transaction.segments) + 1 or number > transaction.expected_segments:
            raise _Refusal("091104", text="unexpected segment number")
        transaction.segments.append(
            root.findtext("e:body/e:DataTransfer/e:OrderData", namespaces=_NS) or ""
        )
        last = segment.get("lastSegment") == "true"
        if last:
            del self._transactions[transaction_id]
            self._accept_upload(transaction)
        return self._response(
            "Transfer",
            transaction_id=transaction_id,
            segment=(number, last),
            order_id=transaction.order_id,
        )

    def _accept_upload(self, transaction: _Transaction) -> None:
        encrypted = b"".join(base64.b64decode(s) for s in transaction.segments)
        data = zlib.decompress(_aes(transaction.transaction_key, encrypted, encrypt=False))
        if hashlib.sha256(_hash_input(data)).digest() != transaction.data_digest:
            raise _Refusal(business="091301", text="DataDigest does not match the order data")
        signature_xml = _parse(
            zlib.decompress(
                _aes(transaction.transaction_key, transaction.signature_data, encrypt=False)
            )
        )
        value = (
            signature_xml.findtext("s:OrderSignatureData/s:SignatureValue", namespaces=_NS) or ""
        )
        certificate = transaction.subscriber.signature_certificate
        if certificate is None or not _a006_ok(certificate, base64.b64decode(value), data):
            raise _Refusal(business="091301", text="electronic signature does not verify")
        if transaction.service is None:
            raise _Refusal("061099", text="upload without service")
        self.uploads.append(
            ReceivedUpload(
                order_id=transaction.order_id,
                service=transaction.service,
                data=data,
                file_name=transaction.file_name,
                partner_id=transaction.subscriber.partner_id,
                user_id=transaction.subscriber.user_id,
                signature_verified=True,
            )
        )

    # Responses --------------------------------------------------------------------

    def _next_order_id(self) -> str:
        self._order_counter += 1
        return f"A{self._order_counter:03d}"

    def _response(
        self,
        phase: str,
        technical: str = "000000",
        business: str = "000000",
        text: str = "",
        transaction_id: str | None = None,
        num_segments: int | None = None,
        segment: tuple[int, bool] | None = None,
        order_id: str | None = None,
        data: tuple[x509.Certificate | None, bytes | None, str] | None = None,
    ) -> bytes:
        root = etree.Element(
            _q("ebicsResponse"),
            nsmap=cast("dict[str, str]", {None: H005, "ds": DS}),
            Version="H005",
            Revision="1",
        )
        header = etree.SubElement(root, _q("header"), authenticate="true")
        static = etree.SubElement(header, _q("static"))
        if transaction_id:
            etree.SubElement(static, _q("TransactionID")).text = transaction_id
        if num_segments is not None:
            etree.SubElement(static, _q("NumSegments")).text = str(num_segments)
        mutable = etree.SubElement(header, _q("mutable"))
        etree.SubElement(mutable, _q("TransactionPhase")).text = phase
        if segment is not None:
            number = etree.SubElement(
                mutable, _q("SegmentNumber"), lastSegment="true" if segment[1] else "false"
            )
            number.text = str(segment[0])
        if order_id:
            etree.SubElement(mutable, _q("OrderID")).text = order_id
        etree.SubElement(mutable, _q("ReturnCode")).text = technical
        etree.SubElement(mutable, _q("ReportText")).text = text or "[EBICS_OK] OK"
        body = etree.SubElement(root, _q("body"))
        if data is not None:
            self._data_transfer(body, *data)
        etree.SubElement(body, _q("ReturnCode"), authenticate="true").text = business
        self._sign(root)
        if self.tamper_content:
            business_code = _need(body.find(_q("ReturnCode")))
            business_code.text = "000000" if business != "000000" else "091116"
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8")

    def _sign(self, root: etree._Element) -> None:
        signature = etree.Element(_q("AuthSignature"))
        info = etree.SubElement(signature, _q("SignedInfo", DS))
        etree.SubElement(info, _q("CanonicalizationMethod", DS), Algorithm=_C14N)
        etree.SubElement(info, _q("SignatureMethod", DS), Algorithm=_RSA_SHA256)
        reference = etree.SubElement(
            info, _q("Reference", DS), URI="#xpointer(//*[@authenticate='true'])"
        )
        transforms = etree.SubElement(reference, _q("Transforms", DS))
        etree.SubElement(transforms, _q("Transform", DS), Algorithm=_C14N)
        etree.SubElement(reference, _q("DigestMethod", DS), Algorithm=_SHA256)
        etree.SubElement(reference, _q("DigestValue", DS)).text = _b64(_auth_digest(root))
        value = etree.SubElement(signature, _q("SignatureValue", DS))
        header = _need(root.find(_q("header")))
        header.addnext(signature)
        raw = self.authentication_key.sign(_c14n(info), padding.PKCS1v15(), hashes.SHA256())
        if self.tamper_signatures:
            raw = bytes([raw[0] ^ 0xFF]) + raw[1:]
        value.text = _b64(raw)
