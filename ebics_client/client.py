"""EbicsClient: key management, BTD downloads and BTU uploads over EBICS 3.0 (H005)."""

from __future__ import annotations

import hmac
import io
import urllib.error
import urllib.request
import zipfile
import zlib
from datetime import date
from typing import Callable

from . import crypto, requests, responses, xmlsig
from .errors import BankKeysNotVerified, EbicsError, SignatureInvalid, UploadsDisabled
from .keyring import Bank, Keyring, User
from .letter import bank_key_hashes
from .service import Service

__all__ = ["EbicsClient", "HttpTransport", "Transport"]

#: A transport posts an EBICS message to a URL and returns the answer's body.
Transport = Callable[[str, bytes], bytes]

#: Unpacked ZIP containers larger than this are refused (zip bomb guard).
MAX_UNPACKED_SIZE = 1 << 30

#: Default cap of an HTTP answer: one EBICS segment is about 1 MB of base64.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class HttpTransport:
    """Default transport: HTTPS POST with urllib, content type text/xml; charset=UTF-8."""

    def __init__(
        self,
        timeout: float = 30.0,
        allow_insecure_http: bool = False,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        """timeout is in seconds; plain http:// is refused unless allow_insecure_http.

        An answer longer than max_response_bytes (default 64 MiB) raises EbicsError.
        """
        self.timeout = timeout
        self.allow_insecure_http = allow_insecure_http
        self.max_response_bytes = max_response_bytes

    def __call__(self, url: str, body: bytes) -> bytes:
        """POST body to url and return the response body."""
        if not url.startswith("https://") and not (
            self.allow_insecure_http and url.startswith("http://")
        ):
            raise EbicsError(text=f"refusing to send EBICS data to a non-HTTPS URL: {url}")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "text/xml; charset=UTF-8"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as answer:
                data: bytes = answer.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            raise EbicsError(text=f"HTTP {exc.code} from {url}") from exc
        except urllib.error.URLError as exc:
            raise EbicsError(text=f"cannot reach {url}: {exc.reason}") from exc
        if len(data) > self.max_response_bytes:
            raise EbicsError(
                text=f"the answer from {url} is more than {self.max_response_bytes} bytes, refused"
            )
        return data


def _unzip(data: bytes) -> list[bytes]:
    """Unpack a ZIP container; every failure becomes an EbicsError (negative receipt)."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError) as exc:
        raise EbicsError(text="the bank announced a ZIP container but sent no ZIP data") from exc
    entries = [info for info in archive.infolist() if not info.is_dir()]
    if sum(info.file_size for info in entries) > MAX_UNPACKED_SIZE:
        raise EbicsError(text="the ZIP container unpacks to more than 1 GiB, refused")
    try:
        return [archive.read(info) for info in entries]
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        NotImplementedError,
        RuntimeError,
        zlib.error,
        ValueError,
        EOFError,
        OSError,
    ) as exc:
        raise EbicsError(text=f"the ZIP container could not be unpacked: {exc}") from exc


class EbicsClient:
    """An EBICS 3.0 subscriber talking to one bank.

    Safety defaults: uploads raise UploadsDisabled unless allow_uploads=True, and
    downloads and uploads raise BankKeysNotVerified until keyring.bank_keys_verified
    is True (set it after comparing the HPB hashes with the bank's letter), unless
    require_verified_bank_keys=False. Every ebicsResponse must carry a valid X002
    signature of the bank, otherwise SignatureInvalid is raised.
    """

    def __init__(
        self,
        bank: Bank,
        user: User,
        keyring: Keyring,
        transport: Transport | None = None,
        allow_uploads: bool = False,
        require_verified_bank_keys: bool = True,
        timeout: float = 30.0,
        product: str = "python-ebics-client 0.1.0",
        language: str = "en",
    ) -> None:
        """transport defaults to HttpTransport(timeout); product and language fill Product."""
        self.bank = bank
        self.user = user
        self.keyring = keyring
        self.transport: Transport = transport or HttpTransport(timeout=timeout)
        self.allow_uploads = allow_uploads
        self.require_verified_bank_keys = require_verified_bank_keys
        self.context = requests.RequestContext.create(bank, user, product, language)

    # Plumbing -----------------------------------------------------------------

    def _post(self, body: bytes) -> bytes:
        return self.transport(self.bank.url, body)

    def _exchange(self, body: bytes) -> responses.Response:
        """Send an ebicsRequest; verify the bank's X002 signature, then the codes."""
        answer = responses.parse_response(self._post(body))
        if answer.kind != "ebicsResponse":
            raise EbicsError(text=f"expected ebicsResponse, got {answer.kind}")
        try:
            xmlsig.verify(answer.root, self.keyring.bank_authentication_key())
        except SignatureInvalid as exc:
            # The codes cannot be trusted without the signature, but they often
            # explain the failure (e.g. a key update), so report them, marked as such.
            raise SignatureInvalid(
                text=f"{exc.text} (unverified bank answer: technical "
                f"{answer.technical_code or '-'}, business {answer.business_code or '-'}, "
                f"report text {answer.report_text!r})"
            ) from exc
        answer.raise_for_codes()
        return answer

    def _key_management(self, body: bytes) -> responses.Response:
        """Send a key management request; its answer carries no AuthSignature (XSD)."""
        answer = responses.parse_response(self._post(body))
        if answer.kind != "ebicsKeyManagementResponse":
            raise EbicsError(text=f"expected ebicsKeyManagementResponse, got {answer.kind}")
        answer.raise_for_codes()
        return answer

    def _check_bank_keys(self) -> None:
        self.keyring.bank_certificates()  # raises KeyringError before HPB
        if self.require_verified_bank_keys and not self.keyring.bank_keys_verified:
            raise BankKeysNotVerified(
                text="compare letter.bank_key_hashes(keyring) with the bank's letter, "
                "then set keyring.bank_keys_verified = True"
            )

    def _check_encryption_digest(self, answer: responses.Response) -> None:
        expected = crypto.certificate_digest(self.keyring.encryption_certificate)
        found = answer.encryption_pubkey_digest
        if found is None or not hmac.compare_digest(found, expected):
            raise SignatureInvalid(text="the bank encrypted for another E002 key than ours")

    # Key management -----------------------------------------------------------

    def hev(self) -> list[responses.ProtocolVersion]:
        """Ask which EBICS versions the bank supports (HEV)."""
        return responses.parse_hev(self._post(requests.build_hev(self.bank.host_id)))

    def ini(self) -> str | None:
        """Send the A006 signature certificate (INI). Returns the order id, if any."""
        return self._key_management(requests.build_ini(self.context, self.keyring)).order_id

    def hia(self) -> str | None:
        """Send the X002 and E002 certificates (HIA). Returns the order id, if any."""
        return self._key_management(requests.build_hia(self.context, self.keyring)).order_id

    def h3k(self) -> str | None:
        """Send all three certificates at once (H3K), for CA-issued certificates."""
        return self._key_management(requests.build_h3k(self.context, self.keyring)).order_id

    def hpb(self) -> dict[str, str]:
        """Fetch the bank's X002 and E002 certificates and store them in the keyring.

        Returns their SHA-256 hashes ({"X002": ..., "E002": ...}) to compare with the
        bank's letter. New certificates are stored unverified; fetching the same
        certificates again keeps the verified flag.
        """
        answer = self._key_management(requests.build_hpb(self.context, self.keyring))
        if answer.order_data is None or answer.transaction_key is None:
            raise EbicsError(text="HPB answer carries no order data")
        self._check_encryption_digest(answer)
        data = responses.decrypt_order_data(
            self.keyring.encryption_key,
            answer.transaction_key,
            responses.decode_segments([answer.order_data]),
        )
        certificates = responses.parse_hpb_order_data(data)
        if certificates.host_id != self.bank.host_id:
            raise EbicsError(
                text=f"HPB answer is for host {certificates.host_id or '(none)'}, "
                f"not {self.bank.host_id}"
            )
        unchanged = (
            self.keyring.bank_authentication_certificate == certificates.authentication
            and self.keyring.bank_encryption_certificate == certificates.encryption
        )
        verified = self.keyring.bank_keys_verified and unchanged
        self.keyring.set_bank_certificates(certificates.authentication, certificates.encryption)
        self.keyring.bank_keys_verified = verified
        return bank_key_hashes(self.keyring)

    # Business transactions ----------------------------------------------------

    def download(
        self,
        service: Service,
        start: date | None = None,
        end: date | None = None,
        unzip: bool = True,
    ) -> list[bytes]:
        """Download the files available for service (BTD), optionally for a date range.

        Returns the bytes of each file; a ZIP container is unpacked unless unzip is
        False. Raises NoDownloadData (090005) when the bank has nothing new. The
        download is acknowledged (receipt 0) only after it was decrypted and
        unpacked; otherwise the bank gets receipt 1 and keeps the data.
        """
        self._check_bank_keys()
        first = self._exchange(
            requests.build_btd_init(self.context, self.keyring, service, start, end)
        )
        transaction_id = first.transaction_id
        if not transaction_id or first.order_data is None or first.transaction_key is None:
            raise EbicsError(text="BTD answer carries no transaction or order data")
        self._check_encryption_digest(first)
        total = first.num_segments or 1
        segments = [first.order_data]
        for number in range(2, total + 1):
            answer = self._exchange(
                requests.build_download_transfer(
                    self.context, self.keyring, transaction_id, number, number == total
                )
            )
            if (
                answer.transaction_id not in (None, transaction_id)
                or answer.segment_number != number
                or answer.order_data is None
            ):
                raise EbicsError(text=f"expected segment {number} of {total}")
            segments.append(answer.order_data)

        try:
            data = responses.decrypt_order_data(
                self.keyring.encryption_key,
                first.transaction_key,
                responses.decode_segments(segments),
            )
            files = _unzip(data) if unzip and service.container == "ZIP" else [data]
        except EbicsError:
            self._receipt(transaction_id, acknowledged=False)
            raise
        self._receipt(transaction_id, acknowledged=True)
        return files

    def _receipt(self, transaction_id: str, acknowledged: bool) -> None:
        self._exchange(
            requests.build_receipt(self.context, self.keyring, transaction_id, acknowledged)
        )

    def upload(
        self,
        service: Service,
        data: bytes,
        file_name: str | None = None,
        signature_flag: bool = True,
    ) -> str:
        """Upload data for service (BTU) with our A006 signature; returns the order id.

        Refused with UploadsDisabled unless the client was created with
        allow_uploads=True: an upload can move money. CR, LF and Ctrl-Z are removed
        from data before signing (EBICS banks hash order data that way) and the
        normalized bytes are what is sent, so the file the bank receives has no
        line breaks.
        """
        if not self.allow_uploads:
            raise UploadsDisabled(
                text="uploads are disabled, create the client with allow_uploads=True"
            )
        self._check_bank_keys()
        payload = requests.prepare_upload(self.context, self.keyring, data)
        first = self._exchange(
            requests.build_btu_init(
                self.context, self.keyring, service, payload, file_name, signature_flag
            )
        )
        transaction_id = first.transaction_id
        if not transaction_id:
            raise EbicsError(text="BTU answer carries no transaction id")
        order_id = first.order_id
        total = len(payload.segments)
        for number, segment in enumerate(payload.segments, start=1):
            answer = self._exchange(
                requests.build_upload_transfer(
                    self.context, self.keyring, transaction_id, number, number == total, segment
                )
            )
            order_id = answer.order_id or order_id
        if not order_id:
            raise EbicsError(text="the bank accepted the upload without an order id")
        return order_id
