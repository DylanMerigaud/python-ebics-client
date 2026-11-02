"""Exceptions raised by the client."""

from __future__ import annotations

__all__ = [
    "RETURN_CODES",
    "BankKeysNotVerified",
    "EbicsBusinessError",
    "EbicsError",
    "EbicsTechnicalError",
    "KeyringError",
    "NoDownloadData",
    "SignatureInvalid",
    "UploadsDisabled",
]

#: Symbolic names of the EBICS return codes this library meets most often
#: (EBICS 3.0 specification, appendix "Return codes").
RETURN_CODES: dict[str, str] = {
    "000000": "EBICS_OK",
    "011000": "EBICS_DOWNLOAD_POSTPROCESS_DONE",
    "011001": "EBICS_DOWNLOAD_POSTPROCESS_SKIPPED",
    "011101": "EBICS_TX_SEGMENT_NUMBER_UNDERRUN",
    "031001": "EBICS_ORDER_PARAMS_IGNORED",
    "061001": "EBICS_AUTHENTICATION_FAILED",
    "061002": "EBICS_INVALID_REQUEST",
    "061099": "EBICS_INTERNAL_ERROR",
    "061101": "EBICS_TX_RECOVERY_SYNC",
    "091002": "EBICS_INVALID_USER_OR_USER_STATE",
    "091003": "EBICS_USER_UNKNOWN",
    "091004": "EBICS_INVALID_USER_STATE",
    "091005": "EBICS_INVALID_ORDER_TYPE",
    "091006": "EBICS_UNSUPPORTED_ORDER_TYPE",
    "091008": "EBICS_BANK_PUBKEY_UPDATE_REQUIRED",
    "091009": "EBICS_SEGMENT_SIZE_EXCEEDED",
    "091010": "EBICS_INVALID_XML",
    "091011": "EBICS_INVALID_HOST_ID",
    "091101": "EBICS_TX_UNKNOWN_TXID",
    "091102": "EBICS_TX_ABORT",
    "091103": "EBICS_TX_MESSAGE_REPLAY",
    "091104": "EBICS_TX_SEGMENT_NUMBER_EXCEEDED",
    "091112": "EBICS_INVALID_ORDER_PARAMS",
    "091113": "EBICS_INVALID_REQUEST_CONTENT",
    "091117": "EBICS_MAX_ORDER_DATA_SIZE_EXCEEDED",
    "091118": "EBICS_MAX_SEGMENTS_EXCEEDED",
    "091119": "EBICS_MAX_TRANSACTIONS_EXCEEDED",
    "091120": "EBICS_PARTNER_ID_MISMATCH",
    "091121": "EBICS_INCOMPATIBLE_ORDER_ATTRIBUTE",
    "090003": "EBICS_AUTHORISATION_ORDER_TYPE_FAILED",
    "090004": "EBICS_INVALID_ORDER_DATA_FORMAT",
    "090005": "EBICS_NO_DOWNLOAD_DATA_AVAILABLE",
    "090006": "EBICS_UNSUPPORTED_REQUEST_FOR_ORDER_INSTANCE",
    "091105": "EBICS_RECOVERY_NOT_SUPPORTED",
    "091116": "EBICS_PROCESSING_ERROR",
    "091201": "EBICS_KEYMGMT_UNSUPPORTED_VERSION_SIGNATURE",
    "091202": "EBICS_KEYMGMT_UNSUPPORTED_VERSION_AUTHENTICATION",
    "091203": "EBICS_KEYMGMT_UNSUPPORTED_VERSION_ENCRYPTION",
    "091204": "EBICS_KEYMGMT_KEYLENGTH_ERROR_SIGNATURE",
    "091205": "EBICS_KEYMGMT_KEYLENGTH_ERROR_AUTHENTICATION",
    "091206": "EBICS_KEYMGMT_KEYLENGTH_ERROR_ENCRYPTION",
    "091207": "EBICS_KEYMGMT_NO_X509_SUPPORT",
    "091208": "EBICS_X509_CERTIFICATE_EXPIRED",
    "091209": "EBICS_X509_CERTIFICATE_NOT_VALID_YET",
    "091210": "EBICS_X509_WRONG_KEY_USAGE",
    "091211": "EBICS_X509_WRONG_ALGORITHM",
    "091212": "EBICS_X509_INVALID_THUMBPRINT",
    "091213": "EBICS_X509_CTL_INVALID",
    "091214": "EBICS_X509_UNKNOWN_CERTIFICATE_AUTHORITY",
    "091215": "EBICS_X509_INVALID_POLICY",
    "091216": "EBICS_X509_INVALID_BASIC_CONSTRAINTS",
    "091217": "EBICS_ONLY_X509_SUPPORT",
    "091218": "EBICS_KEYMGMT_DUPLICATE_KEY",
    "091219": "EBICS_CERTIFICATES_VALIDATION_ERROR",
    "091301": "EBICS_SIGNATURE_VERIFICATION_FAILED",
    "091302": "EBICS_ACCOUNT_AUTHORISATION_FAILED",
    "091303": "EBICS_AMOUNT_CHECK_FAILED",
    "091304": "EBICS_SIGNER_UNKNOWN",
    "091305": "EBICS_INVALID_SIGNER_STATE",
    "091306": "EBICS_DUPLICATE_SIGNATURE",
}


class EbicsError(Exception):
    """Base class of every error the library raises on purpose.

    code is the six digit EBICS return code when the bank sent one, otherwise "".
    """

    def __init__(self, code: str = "", text: str = "") -> None:
        self.code = code
        self.text = text or RETURN_CODES.get(code, "")
        super().__init__(f"{code} {self.text}".strip())


class EbicsTechnicalError(EbicsError):
    """The bank answered with a technical return code (header/mutable/ReturnCode)."""


class EbicsBusinessError(EbicsError):
    """The bank answered with a business return code (body/ReturnCode)."""


class NoDownloadData(EbicsBusinessError):
    """090005: the bank has nothing to download for this request."""

    def __init__(self, code: str = "090005", text: str = "") -> None:
        super().__init__(code, text)


class UploadsDisabled(EbicsError):
    """Uploads are refused unless the client was created with allow_uploads=True."""


class BankKeysNotVerified(EbicsError):
    """The bank keys were not verified against the bank's letter yet."""


class SignatureInvalid(EbicsError):
    """A signature or digest from the bank did not verify."""


class KeyringError(EbicsError):
    """The keyring is missing a key, holds a mismatched one or cannot be decrypted."""
