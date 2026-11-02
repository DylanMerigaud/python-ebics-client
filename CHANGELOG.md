# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-02

First release (alpha). Tested against the official EBICS H005 schemas and an in-process test
bank, not yet against a production bank.

### Added

- EBICS 3.0 (H005) client `EbicsClient` with HEV, INI, HIA, H3K, HPB, BTD downloads and BTU
  uploads.
- Key generation: A006 (signature), X002 (authentication) and E002 (encryption) RSA keys with
  self-signed X.509 certificates; loading of CA-issued certificates for H3K.
- X002 authentication signature on every request, verified on every bank response.
- Order data encryption and decryption (E002, AES-128-CBC with the EBICS padding), zlib
  compression, A006 signature (RSASSA-PSS, SHA-256) on uploads.
- BTD downloads with several segments, receipts, and unpacking of ZIP containers.
- BTU uploads with segmentation and an optional file name, behind `allow_uploads=True`.
  CR, LF and Ctrl-Z are removed from the order data once, before signing, and that normalized
  document is what is signed (A006), digested (DataDigest) and sent, as railslove/epics does:
  the file the bank receives has no line breaks.
- `Service` BTF presets for Switzerland and Germany: camt.052, camt.053, camt.054, pain.001,
  pain.008.
- INI and HIA letters with the SHA-256 certificate hashes, and `letter.bank_key_hashes` to
  compare the bank's keys after HPB.
- `Keyring` with `save` and `load` (private keys encrypted with a passphrase, file mode 600).
- Safety defaults: uploads off, downloads and uploads refused until the bank keys are marked
  verified, HTTPS only for the default transport.
- `ebics_client.testing.FakeBank`, an in-process H005 bank for tests and offline examples.
- Typed package (`py.typed`), Python 3.9 to 3.13, runtime dependencies `cryptography` and
  `lxml`.
- Every request and every FakeBank response is validated against the H005 XSDs in the tests.

[0.1.0]: https://github.com/DylanMerigaud/python-ebics-client/releases/tag/v0.1.0
