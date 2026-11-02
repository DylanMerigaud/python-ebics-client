from __future__ import annotations

import io
import os
import urllib.request
import zipfile
from datetime import date
from pathlib import Path

import pytest
from lxml import etree

from ebics_client import (
    BankKeysNotVerified,
    EbicsBusinessError,
    EbicsClient,
    EbicsError,
    EbicsTechnicalError,
    HttpTransport,
    Keyring,
    KeyringError,
    NoDownloadData,
    Service,
    SignatureInvalid,
    UploadsDisabled,
    User,
    crypto,
    letter,
)
from ebics_client.testing import FakeBank, sample_camt053
from tests.conftest import assert_valid, pooled_key

USER = User(partner_id="PARTNER1", user_id="USER1")
H000 = "http://www.ebics.org/H000"


class Recorder:
    """Transport that validates every request and response against the H005 XSD."""

    def __init__(self, bank: FakeBank) -> None:
        self.bank = bank
        self.exchanges: list[tuple[bytes, bytes]] = []

    def __call__(self, url: str, body: bytes) -> bytes:
        if etree.QName(etree.fromstring(body)).namespace != H000:
            assert_valid(body)
        answer = self.bank(url, body)
        if etree.QName(etree.fromstring(answer)).namespace != H000:
            assert_valid(answer)
        self.exchanges.append((body, answer))
        return answer

    def order_types(self) -> list[str]:
        found = []
        for body, _ in self.exchanges:
            root = etree.fromstring(body)
            node = root.find(".//{urn:org:ebics:H005}AdminOrderType")
            phase = root.find(".//{urn:org:ebics:H005}TransactionPhase")
            if phase is not None and phase.text != "Initialisation":
                found.append(phase.text or "")
            else:
                found.append(node.text or "" if node is not None else etree.QName(root).localname)
        return found


def new_bank() -> FakeBank:
    return FakeBank(authentication_key=pooled_key(3), encryption_key=pooled_key(4))


def new_keyring() -> Keyring:
    return Keyring.from_keys(USER, pooled_key(0), pooled_key(1), pooled_key(2), "CH")


def make_client(bank: FakeBank, **options: object) -> tuple[EbicsClient, Recorder]:
    recorder = Recorder(bank)
    client = EbicsClient(bank.bank, USER, new_keyring(), transport=recorder, **options)  # type: ignore[arg-type]
    return client, recorder


def onboarded(bank: FakeBank, **options: object) -> tuple[EbicsClient, Recorder]:
    client, recorder = make_client(bank, **options)
    bank.onboard(client)
    return client, recorder


def test_hev() -> None:
    client, _ = make_client(new_bank())
    versions = client.hev()
    assert [(v.protocol, v.version) for v in versions] == [("H005", "03.00")]


def test_ini_hia_hpb_flow_stores_unverified_bank_keys() -> None:
    bank = new_bank()
    client, recorder = make_client(bank)
    client.ini()
    client.hia()
    subscriber = bank.subscriber("PARTNER1", "USER1")
    assert subscriber.signature_certificate == client.keyring.signature_certificate
    assert subscriber.authentication_certificate == client.keyring.authentication_certificate
    assert subscriber.encryption_certificate == client.keyring.encryption_certificate
    hashes = client.hpb()
    assert hashes == bank.key_hashes()
    assert hashes == letter.bank_key_hashes(client.keyring)
    assert client.keyring.bank_authentication_certificate == bank.authentication_certificate
    assert client.keyring.bank_keys_verified is False
    assert recorder.order_types() == ["INI", "HIA", "HPB"]


def test_h3k_replaces_ini_and_hia() -> None:
    bank = new_bank()
    client, recorder = make_client(bank)
    client.h3k()
    subscriber = bank.subscriber("PARTNER1", "USER1")
    assert subscriber.ready
    assert subscriber.signature_certificate == client.keyring.signature_certificate
    client.hpb()
    assert recorder.order_types() == ["H3K", "HPB"]


def test_h3k_with_bad_signature_refused() -> None:
    bank = new_bank()
    client, _ = make_client(bank)
    # A signature certificate that does not match the key signing the order data.
    other = Keyring.from_keys(USER, pooled_key(5), pooled_key(1), pooled_key(2))
    client.keyring.signature_certificate = other.signature_certificate
    with pytest.raises(EbicsBusinessError) as info:
        client.h3k()
    assert info.value.code == "091301"


def test_hpb_before_hia_is_refused_by_bank() -> None:
    client, _ = make_client(new_bank())
    client.ini()
    with pytest.raises(EbicsTechnicalError) as info:
        client.hpb()
    assert info.value.code == "091002"


def test_onboard_marks_keys_verified() -> None:
    bank = new_bank()
    client, _ = onboarded(bank)
    assert client.keyring.bank_keys_verified is True


def test_download_single_segment_zip_unpacked() -> None:
    bank = new_bank()
    statement = sample_camt053()
    bank.register_download(Service.CAMT_053_CH, statement)
    client, recorder = onboarded(bank)
    files = client.download(Service.CAMT_053_CH, start=date(2026, 10, 1), end=date(2026, 10, 31))
    assert files == [statement]
    assert bank.last_date_range == (date(2026, 10, 1), date(2026, 10, 31))
    assert recorder.order_types()[-2:] == ["BTD", "Receipt"]
    # Acknowledged: nothing left.
    with pytest.raises(NoDownloadData):
        client.download(Service.CAMT_053_CH)


def test_download_three_segments() -> None:
    bank = new_bank()
    payload = os.urandom(3000)
    service = Service("EOP", "mt940", scope="DE")
    bank.register_download(service, payload, segment_size=1100)
    client, recorder = onboarded(bank)
    assert client.download(service) == [payload]
    assert recorder.order_types()[-4:] == ["BTD", "Transfer", "Transfer", "Receipt"]


def test_download_zip_with_several_files() -> None:
    bank = new_bank()
    bank.register_download(Service.CAMT_054_CH, b"<a/>")
    bank.register_download(Service.CAMT_054_CH, b"<b/>")
    client, _ = onboarded(bank)
    assert client.download(Service.CAMT_054_CH) == [b"<a/>", b"<b/>"]


def test_download_raw_zip_when_asked() -> None:
    bank = new_bank()
    bank.register_download(Service.CAMT_053_CH, b"<a/>")
    client, _ = onboarded(bank)
    (raw,) = client.download(Service.CAMT_053_CH, unzip=False)
    archive = zipfile.ZipFile(io.BytesIO(raw))
    assert [archive.read(name) for name in archive.namelist()] == [b"<a/>"]


def test_no_download_data() -> None:
    client, _ = onboarded(new_bank())
    with pytest.raises(NoDownloadData) as info:
        client.download(Service.CAMT_053_CH)
    assert info.value.code == "090005"


def test_other_service_is_not_served() -> None:
    bank = new_bank()
    bank.register_download(Service.CAMT_053_DE, b"<de/>")
    client, _ = onboarded(bank)
    with pytest.raises(NoDownloadData):
        client.download(Service.CAMT_053_CH)


def test_download_refused_while_bank_keys_unverified() -> None:
    bank = new_bank()
    bank.register_download(Service.CAMT_053_CH, b"<a/>")
    client, recorder = make_client(bank)
    client.ini()
    client.hia()
    client.hpb()
    sent = len(recorder.exchanges)
    with pytest.raises(BankKeysNotVerified):
        client.download(Service.CAMT_053_CH)
    assert len(recorder.exchanges) == sent  # nothing was sent


def test_download_allowed_unverified_when_opted_out() -> None:
    bank = new_bank()
    bank.register_download(Service.CAMT_053_CH, b"<a/>")
    client, _ = make_client(bank, require_verified_bank_keys=False)
    client.ini()
    client.hia()
    client.hpb()
    assert client.download(Service.CAMT_053_CH) == [b"<a/>"]


def test_download_without_hpb_refused() -> None:
    client, _ = make_client(new_bank(), require_verified_bank_keys=False)
    with pytest.raises(KeyringError):
        client.download(Service.CAMT_053_CH)


def test_tampered_bank_signature_refused() -> None:
    bank = new_bank()
    bank.register_download(Service.CAMT_053_CH, b"<a/>")
    client, _ = onboarded(bank)
    bank.tamper_signatures = True
    with pytest.raises(SignatureInvalid):
        client.download(Service.CAMT_053_CH)


def test_response_signed_with_unknown_key_refused() -> None:
    bank = new_bank()
    bank.register_download(Service.CAMT_053_CH, b"<a/>")
    client, _ = onboarded(bank)
    bank.rotate_keys(authentication_key=pooled_key(5))
    with pytest.raises(SignatureInvalid):
        client.download(Service.CAMT_053_CH)


def test_tampered_authenticated_content_refused() -> None:
    bank = new_bank()
    client, _ = onboarded(bank)
    bank.tamper_content = True
    with pytest.raises(SignatureInvalid):
        client.download(Service.CAMT_053_CH)


def test_uploads_disabled_by_default() -> None:
    bank = new_bank()
    client, recorder = onboarded(bank)
    sent = len(recorder.exchanges)
    with pytest.raises(UploadsDisabled):
        client.upload(Service.PAIN_001_CH, b"<Document/>")
    assert len(recorder.exchanges) == sent
    assert bank.uploads == []


def test_upload_verified_by_bank() -> None:
    bank = new_bank()
    client, recorder = onboarded(bank, allow_uploads=True)
    document = b"<?xml version='1.0'?><Document><pain/></Document>"
    order_id = client.upload(Service.PAIN_001_CH, document, file_name="pain001.xml")
    (received,) = bank.uploads
    assert received.order_id == order_id
    assert received.data == document
    assert received.service == Service.PAIN_001_CH
    assert received.file_name == "pain001.xml"
    assert received.signature_verified
    assert recorder.order_types()[-2:] == ["BTU", "Transfer"]


PRETTY_PAIN001 = (
    b'<?xml version="1.0" encoding="UTF-8"?>\r\n'
    b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09">\r\n'
    b"  <CstmrCdtTrfInitn>\r\n"
    b"    <GrpHdr>\r\n"
    b"      <MsgId>MSG-1</MsgId>\r\n"
    b"      <NbOfTxs>1</NbOfTxs>\r\n"
    b"    </GrpHdr>\r\n"
    b"  </CstmrCdtTrfInitn>\r\n"
    b"</Document>\r\n"
)


def test_upload_pretty_printed_crlf_document_is_normalized_once() -> None:
    bank = new_bank()
    client, _ = onboarded(bank, allow_uploads=True)
    client.upload(Service.PAIN_001_CH, PRETTY_PAIN001)
    (received,) = bank.uploads
    # FakeBank hashes exactly what it decrypted: signature and digest cover these bytes.
    assert received.data == crypto.normalize_order_data(PRETTY_PAIN001)
    assert b"\r" not in received.data and b"\n" not in received.data
    assert received.data.startswith(b'<?xml version="1.0" encoding="UTF-8"?><Document')
    assert received.signature_verified


def test_upload_in_several_segments() -> None:
    bank = new_bank()
    client, recorder = onboarded(bank, allow_uploads=True)
    document = os.urandom(2_200_000)
    client.upload(Service.PAIN_001_DE, document)
    assert bank.uploads[0].data == crypto.normalize_order_data(document)
    assert recorder.order_types()[-4:] == ["BTU", "Transfer", "Transfer", "Transfer"]


def test_upload_refused_while_bank_keys_unverified() -> None:
    bank = new_bank()
    client, _ = make_client(bank, allow_uploads=True)
    client.ini()
    client.hia()
    client.hpb()
    with pytest.raises(BankKeysNotVerified):
        client.upload(Service.PAIN_001_CH, b"<Document/>")


def test_upload_with_wrong_signature_key_rejected_by_bank() -> None:
    bank = new_bank()
    client, _ = onboarded(bank, allow_uploads=True)
    client.keyring.signature_key = pooled_key(5)  # bank still holds the INI certificate
    with pytest.raises(EbicsBusinessError) as info:
        client.upload(Service.PAIN_001_CH, b"<Document/>")
    assert info.value.code == "091301"
    assert bank.uploads == []


def test_bank_rejects_wrong_authentication_key() -> None:
    bank = new_bank()
    bank.register_download(Service.CAMT_053_CH, b"<a/>")
    client, _ = onboarded(bank)
    client.keyring.authentication_key = pooled_key(5)
    with pytest.raises(EbicsTechnicalError) as info:
        client.download(Service.CAMT_053_CH)
    assert info.value.code == "061001"


def test_negative_receipt_keeps_the_file(monkeypatch: pytest.MonkeyPatch) -> None:
    bank = new_bank()
    bank.register_download(Service.CAMT_053_CH, b"not a zip", raw=True)
    client, recorder = onboarded(bank)
    with pytest.raises(Exception, match="ZIP"):
        client.download(Service.CAMT_053_CH)
    last_request = etree.fromstring(recorder.exchanges[-1][0])
    assert last_request.findtext(".//{urn:org:ebics:H005}ReceiptCode") == "1"
    assert bank.pending(Service.CAMT_053_CH) == 1


def test_quickstart_path() -> None:
    bank = FakeBank()
    bank.register_download(Service.CAMT_053_CH, sample_camt053())
    user = User(partner_id="PARTNER1", user_id="USER1")
    keyring = Keyring.from_keys(user, pooled_key(0), pooled_key(1), pooled_key(2))
    client = EbicsClient(bank.bank, user, keyring, transport=bank)
    client.ini()
    client.hia()
    client.hpb()
    keyring.bank_keys_verified = True
    (statement,) = client.download(Service.CAMT_053_CH)
    assert b"camt.053" in statement


def test_hpb_again_keeps_verification_when_keys_unchanged() -> None:
    bank = new_bank()
    client, _ = onboarded(bank)
    client.hpb()
    assert client.keyring.bank_keys_verified is True
    bank.rotate_keys(authentication_key=pooled_key(5))
    client.hpb()
    assert client.keyring.bank_keys_verified is False
    assert client.keyring.bank_authentication_certificate == bank.authentication_certificate


def test_hpb_encrypted_for_another_key_refused() -> None:
    bank = new_bank()
    client, _ = make_client(bank)
    client.ini()
    client.hia()
    bank.subscriber("PARTNER1", "USER1").encryption_certificate = (
        Keyring.from_keys(USER, pooled_key(0), pooled_key(1), pooled_key(5)).encryption_certificate
    )
    with pytest.raises(SignatureInvalid):
        client.hpb()
    assert client.keyring.bank_authentication_certificate is None


def test_keyring_persists_between_sessions(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    bank = new_bank()
    bank.register_download(Service.CAMT_053_CH, b"<a/>")
    client, _ = onboarded(bank)
    client.keyring.save(path, passphrase="secret")
    again = EbicsClient(bank.bank, USER, Keyring.load(path, "secret"), transport=bank)
    assert again.download(Service.CAMT_053_CH) == [b"<a/>"]


def test_http_transport_refuses_plain_http() -> None:
    transport = HttpTransport()
    with pytest.raises(EbicsError, match="non-HTTPS"):
        transport("http://bank.example/ebics", b"<x/>")


def test_http_transport_posts_xml(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> io.BytesIO:
        seen["url"] = request.full_url
        seen["type"] = request.get_header("Content-type")
        seen["body"] = request.data
        seen["method"] = request.get_method()
        seen["timeout"] = timeout
        return io.BytesIO(b"<ok/>")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert HttpTransport(timeout=5)("https://bank.example/ebics", b"<x/>") == b"<ok/>"
    assert seen == {
        "url": "https://bank.example/ebics",
        "type": "text/xml; charset=UTF-8",
        "body": b"<x/>",
        "method": "POST",
        "timeout": 5,
    }


def test_onboard_detects_a_substituted_bank_key() -> None:
    bank = new_bank()
    client, _ = make_client(bank)
    real_hpb = client.hpb

    def forged_hpb() -> dict[str, str]:
        hashes = real_hpb()
        hashes["X002"] = "0000"
        return hashes

    client.hpb = forged_hpb  # type: ignore[method-assign]
    with pytest.raises(SignatureInvalid):
        bank.onboard(client)
    assert client.keyring.bank_keys_verified is False
