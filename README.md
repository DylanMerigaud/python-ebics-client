# python-ebics-client

[![CI](https://github.com/DylanMerigaud/python-ebics-client/actions/workflows/ci.yml/badge.svg)](https://github.com/DylanMerigaud/python-ebics-client/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/python-ebics-client.svg)](https://pypi.org/project/python-ebics-client/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure-Python EBICS 3.0 (H005) client for Python developers and ERP integrators who need to
download bank statements (camt.052, camt.053, camt.054) and upload payment files (pain.001,
pain.008) over EBICS with Swiss, German or French banks, without a paid licence and without a
Node.js sidecar. EBICS 2.5 is being switched off in Switzerland (Raiffeisen Switzerland ends
it on 2026-11-13), so a client that speaks H005 is no longer optional there.

It implements EBICS 3.0 (protocol version H005) as specified by EBICS SCRL,
<https://www.ebics.org>.

**Status: version 0.1.0, alpha.** Every request and every response is validated against the
official EBICS H005 XML schemas and exercised end to end against an in-process test bank
(`FakeBank`). It has **not yet been confirmed against a production bank**. Bank interop reports
are welcome: use the
[bank report issue template](https://github.com/DylanMerigaud/python-ebics-client/issues/new?template=bank_report.md).
Uploads are off by default.

## Features

- Key generation: A006, X002 and E002 RSA keys with self-signed X.509 certificates; CA-issued
  certificates can be loaded.
- Key management orders: HEV, INI, HIA, H3K (for CA-issued certificates) and HPB.
- BTD downloads with a date range, several segments, receipts, and ZIP containers unpacked.
- BTU uploads with the A006 electronic signature, segmentation, behind `allow_uploads=True`.
- X002 authentication signature on every request, verified on every bank response.
- Service presets for Switzerland and Germany: camt.052/053/054, pain.001, pain.008.
- INI and HIA letter with the SHA-256 certificate hashes; bank key hashes to compare after HPB.
- Encrypted keyring file (passphrase, PKCS#8, mode 600), or a dict for a database.
- `FakeBank`, an in-process EBICS bank to test your integration offline.
- Fully typed (`py.typed`), Python 3.9 to 3.13, two runtime dependencies: `cryptography` and
  `lxml`.

## Install

```
pip install python-ebics-client
```

## Quickstart

This runs offline against `FakeBank`, a bank that lives in your process:

```python
from datetime import date

from lxml import etree

from ebics_client import EbicsClient, Keyring, Service, User
from ebics_client.testing import FakeBank, sample_camt053

fake = FakeBank()
fake.register_download(Service.CAMT_053_CH, sample_camt053())

user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user, subject_country="CH")
client = EbicsClient(fake.bank, user, keyring, transport=fake)

client.ini()                       # send the signature certificate
client.hia()                       # send the authentication and encryption certificates
hashes = client.hpb()              # fetch the bank's keys
assert hashes == fake.key_hashes() # a real bank: compare with the bank's letter
keyring.bank_keys_verified = True

files = client.download(Service.CAMT_053_CH, start=date(2026, 10, 1), end=date(2026, 10, 31))
statement = etree.fromstring(files[0])
namespace = {"c": "urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"}
print(len(files), "file,", len(statement.findall(".//c:Ntry", namespace)), "entries")
```

## Usage

### Connect to a real bank

Ask your bank for the HostID, the EBICS URL, your PartnerID and UserID. Without a `transport`
the client posts over HTTPS with `urllib` (`HttpTransport`, `timeout` configurable). Any
callable `(url, body) -> bytes` works as a transport.

<!-- harness: skip -->
```python
from ebics_client import Bank, EbicsClient, Keyring, User

bank = Bank(host_id="EBIXHOST", url="https://ebics.example-bank.ch/ebicsweb")
user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.load("keys.json", passphrase="secret")   # created at onboarding
client = EbicsClient(bank, user, keyring)
print(client.hev())                                        # which EBICS versions the bank offers
```

### Onboard a user and print the letter

```python
from ebics_client import EbicsClient, Keyring, User, letter
from ebics_client.testing import FakeBank

fake = FakeBank()
user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user, subject_country="CH")
client = EbicsClient(fake.bank, user, keyring, transport=fake)

client.ini()
client.hia()
print(letter.ini_letter(fake.bank, user, keyring))   # print, sign, send to the bank

# once the bank has activated the user:
hashes = client.hpb()                                # {"X002": "...", "E002": "..."}
print("compare with the bank's letter:", hashes)
if hashes == fake.key_hashes():                      # a real bank: compare by eye or by script
    keyring.bank_keys_verified = True
```

Downloads and uploads raise `BankKeysNotVerified` until `keyring.bank_keys_verified` is
`True`. With CA-issued certificates (France) call `client.h3k()` instead of INI and HIA; see
the [guide](docs/guide.md).

### Download statements for a date range

```python
from datetime import date

from ebics_client import EbicsClient, Keyring, NoDownloadData, Service, User
from ebics_client.testing import FakeBank, sample_camt053

fake = FakeBank()
fake.register_download(Service.CAMT_053_CH, sample_camt053())
user = User(partner_id="PARTNER1", user_id="USER1")
client = EbicsClient(fake.bank, user, Keyring.generate(user), transport=fake)
fake.onboard(client)

files = client.download(Service.CAMT_053_CH, start=date(2026, 10, 1), end=date(2026, 10, 31))
for number, data in enumerate(files, start=1):
    print(f"file {number}: {len(data)} bytes of camt.053")  # write it to disk or parse it
print("date range the bank received:", fake.last_date_range)

try:
    client.download(Service.CAMT_053_CH)
except NoDownloadData:
    print("nothing new at the bank")
```

`download` returns one `bytes` per file, ZIP containers unpacked, and acknowledges the
download to the bank once it was decrypted. Use `Service.CAMT_052_CH`, `CAMT_054_CH` or the
`_DE` presets for other reports, or change a preset: `Service.CAMT_053_CH.with_(msg_version="04")`.
See [docs/order-types.md](docs/order-types.md).

### Upload a payment file

```python
from ebics_client import EbicsClient, Keyring, Service, User
from ebics_client.testing import FakeBank

fake = FakeBank()
user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user)
setup = EbicsClient(fake.bank, user, keyring, transport=fake)
fake.onboard(setup)

pain001 = b"<Document>your pain.001 file</Document>"  # produced by your accounting system
client = EbicsClient(fake.bank, user, keyring, transport=fake, allow_uploads=True)
order_id = client.upload(Service.PAIN_001_CH, pain001, file_name="payments.xml")
print("order id", order_id, "signature checked by the bank:", fake.uploads[-1].signature_verified)
```

Without `allow_uploads=True`, `upload` raises `UploadsDisabled`: an upload can move money. The
file is signed with the A006 key of the user, encrypted and sent; the library does not read or
validate the payment content.

### Save and load the keyring

```python
import os
import tempfile

from ebics_client import Keyring, User

user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user, subject_country="CH")

path = os.path.join(tempfile.mkdtemp(), "keys.json")
keyring.save(path, passphrase="a long passphrase")      # private keys encrypted, file mode 600
restored = Keyring.load(path, passphrase="a long passphrase")
print(restored.bank_keys_verified, restored.signature_certificate == keyring.signature_certificate)
```

`to_dict(passphrase)` and `Keyring.from_dict(data, passphrase)` do the same for a database. A
wrong passphrase raises `KeyringError`.

### Test your integration with FakeBank

`FakeBank` answers HEV, INI, HIA, H3K, HPB, BTD and BTU, verifies the X002 and A006 signatures
of the requests it receives, and can serve large files in several segments.

```python
from ebics_client import EbicsClient, Keyring, Service, SignatureInvalid, User
from ebics_client.testing import FakeBank, sample_camt053

fake = FakeBank()
big = sample_camt053() * 20
fake.register_download(Service.CAMT_053_CH, big, segment_size=2000)  # several segments

user = User(partner_id="PARTNER1", user_id="USER1")
client = EbicsClient(fake.bank, user, Keyring.generate(user), transport=fake)
fake.onboard(client)
print(client.download(Service.CAMT_053_CH)[0] == big)

fake.register_download(Service.CAMT_053_CH, sample_camt053())
fake.tamper_signatures = True            # the client must refuse a forged response
try:
    client.download(Service.CAMT_053_CH)
except SignatureInvalid:
    print("forged response refused")
```

## Why this library

Facts as of 2026-10.

| Library | Language | License | Notes |
|---|---|---|---|
| python-ebics-client (this) | Python | MIT | H005, two runtime dependencies, alpha |
| `fintech` (joonis) | Python | proprietary | the EBICS client needs a paid licence: 100 EUR setup plus 25 EUR a month for the first user; the free mode is limited to 5 transactions per upload and 3 days of statements |
| `ebicsclient` (schulluk) | Python | source-available | paid commercial licence |
| `ebicsPy` 0.1 | Python | AGPL | published 2015, unmaintained |
| node-ebics-client | Node.js | MIT | last push 2025-04 |
| `epics` (railslove) | Ruby | MIT | |
| libfintx | .NET | LGPL | |
| ebics-java-client | Java | LGPL | |

What the others have that this library does not have yet: production-proven coverage of real
banks (this is 0.1.0 and has only met a test bank), the older H004 and H003 protocol versions,
a broader set of order types (HAA, HTD, FDL/FUL and bank specific ones), parsing of camt files
into Python objects, PDF letters, dual-signature (VEU) workflows, and years of use by other
people. What it has: an MIT licence, no payment gate, H005 only and small, typed, two
dependencies, schema-validated messages, and an in-process bank for your own tests.

## Using it in an existing project

These projects use joonis `fintech` for EBICS today (read from their public code, October
2026). They are listed because the mapping is direct, not because they use this library; they
do not. Differences that apply to all four:

- `fintech` returns downloads as a dict (account or file name to bytes); `download` returns a
  `list[bytes]` and acknowledges the download itself, so there is no `confirm_download` call.
- Key files are not interchangeable: a `fintech` keys file cannot be read, so moving over means
  new keys and a new INI/HIA/letter round with the bank.
- The letter is plain text from `letter.ini_letter`, not a PDF.
- H004 order types (`C53`, `Z53`, `FDL`, `FUL`, `download(...)`) and `HTD` have no equivalent;
  the library speaks H005 only.

### libracore/erpnextswiss

`ebics_connection.py` builds a `fintech` keyring, bank, user and client from the connection
document, runs `INI`, `HIA`, `create_ini_letter`, `HPB` and `activate_keys`, and downloads
camt.053 with a `BusinessTransactionFormat(service='EOP', msg_name='camt.053', scope='CH',
container='ZIP')`, which is `Service.CAMT_053_CH`.

```python
from datetime import date

from ebics_client import EbicsClient, Keyring, Service, User, letter
from ebics_client.testing import FakeBank, sample_camt053

fake = FakeBank()   # in the app: Bank(host_id=self.host_id, url=self.url) and no transport=
fake.register_download(Service.CAMT_053_CH, sample_camt053())

# fintech: keyring = EbicsKeyRing(keys=keys_file, passphrase=passphrase)
#          bank = EbicsBank(keyring=keyring, hostid=host_id, url=url)
#          user = EbicsUser(keyring=keyring, partnerid=partner_id, userid=user_id)
#          client = EbicsClient(bank, user, version="H005")
user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user, subject_country="CH")  # fintech: user.create_keys() + create_certificates()
client = EbicsClient(fake.bank, user, keyring, transport=fake)

client.ini()                                            # fintech: client.INI()
client.hia()                                            # fintech: client.HIA()
text = letter.ini_letter(fake.bank, user, keyring)      # fintech: user.create_ini_letter(bankname=..., path=...)
hashes = client.hpb()                                   # fintech: client.HPB()
keyring.bank_keys_verified = hashes == fake.key_hashes()  # fintech: bank.activate_keys()

# fintech: BusinessTransactionFormat(service='EOP', msg_name='camt.053', scope='CH', container='ZIP')
#          data = client.BTD(C53, day, day); client.confirm_download()
day = date(2026, 10, 15)
for file in client.download(Service.CAMT_053_CH, start=day, end=day):
    print(len(file), "bytes of camt.053")
```

For the payment path the project builds a pain.001 `BusinessTransactionFormat(service='MCT',
msg_name='pain.001', scope=...)`; with this library it is
`EbicsClient(..., allow_uploads=True).upload(Service.PAIN_001_CH, xml_bytes)`, which returns the
order id. The `scope` field maps to `Service.PAIN_001_CH.with_(scope=...)`.

### alyf-de/banking

`banking/ebics/manager.py` (branch `version-16-hotfix`) subclasses `EbicsKeyRing` to write the
keys to the database, then maps its request to `client.BTD(BusinessTransactionFormat(service=...,
msg_name=..., scope=country_code, container="ZIP"), start, end)` followed by
`client.confirm_download()`. The database hook becomes `Keyring.to_dict` and `Keyring.from_dict`.

```python
from datetime import date

from ebics_client import EbicsClient, Keyring, Service, User
from ebics_client.testing import FakeBank, sample_camt053

user = User(partner_id="PARTNER1", user_id="USER1")
stored = Keyring.generate(user).to_dict("db-passphrase")   # JSON-ready: save it in a field

# fintech: class CustomKeyRing(EbicsKeyRing): def _write(self, keydict): save_to_db(keydict)
keyring = Keyring.from_dict(stored, "db-passphrase")       # load from the database
# ... after onboarding: save_to_db(keyring.to_dict("db-passphrase"))

fake = FakeBank()   # in the app: Bank(host_id, url)
btf = Service("EOP", "camt.053", scope="CH", container="ZIP")   # service, camt message, country
fake.register_download(btf, sample_camt053())
client = EbicsClient(fake.bank, user, keyring, transport=fake)
fake.onboard(client)

# fintech: btf = BusinessTransactionFormat(service="EOP", msg_name="camt.053", scope="CH", container="ZIP")
#          client.BTD(btf, start, end); client.confirm_download(success=True)
files = client.download(btf, start=date(2026, 10, 1), end=date(2026, 10, 31))
print(len(files), "file(s)")
```

`HTD` (`get_permitted_order_types`) is not implemented; the service to download has to be
configured. The manager also creates `A005` keys; this library generates A006.

### Noviat/account_ebics

`account_ebics/wizards/ebics_xfer.py` (branch `19.0`) stores BTF fields on a file format
record and calls `client.BTD(btf, start=..., end=...)` and `client.BTU(btf, data)`, with
`confirm_download(trans_id=..., success=...)` after each download. The BTF fields map one to
one onto `Service`: `version` is `msg_version`, and `service`, `msg_name`, `scope`, `option`,
`container`, `variant`, `format` keep their names.

```python
from datetime import date

from ebics_client import EbicsClient, Keyring, Service, User
from ebics_client.testing import FakeBank, sample_camt053

fake = FakeBank()   # in the app: the Bank built from the EBICS config record
user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user)
client = EbicsClient(fake.bank, user, keyring, transport=fake, allow_uploads=True)
fake.onboard(client)

# fintech: BusinessTransactionFormat(df.btf_service, df.btf_message, scope=df.btf_scope or None,
#            option=df.btf_option or None, container=df.btf_container or None,
#            version=df.btf_version or None, variant=df.btf_variant or None, format=df.btf_format or None)
btf = Service(
    "EOP", "camt.053",
    scope="CH", option=None, container="ZIP", msg_version="08", variant=None, format=None,
)
fake.register_download(btf, sample_camt053())

# fintech: data = client.BTD(btf, start=date_from, end=date_to); client.confirm_download(...)
files = client.download(btf, start=date(2026, 10, 1), end=date(2026, 10, 31))

# fintech: order_id = client.BTU(btf_upload, upload_data)
upload = Service("MCT", "pain.001", scope="CH", msg_version="09")
order_id = client.upload(upload, b"<Document>pain.001</Document>")
print(len(files), "file(s); uploaded as order", order_id)
```

Not covered: the `TEST="TRUE"` upload parameter, `FDL`/`FUL`, and `H003`/`H004`, which the
module also handles.

### the-efcc/pretix-ebics

`pretix_ebics/ebics.py` wraps `fintech` in a session that writes the keyring blob to a
temporary file and back, calls `INI`, `HIA`, `HPB`, creates the letter as a PDF, and fetches
statements with `client.C53(start=..., end=...)` (an H004 order) followed by
`confirm_download()`. Over H005 the call is a BTD with a camt.053 service, and the keyring blob
can be stored as the string from `to_dict` (no temporary file).

```python
import json
from datetime import date

from ebics_client import EbicsClient, Keyring, Service, User
from ebics_client.testing import FakeBank, sample_camt053

user = User(partner_id="PARTNER1", user_id="USER1")
blob = json.dumps(Keyring.generate(user).to_dict("passphrase"))  # store this string on the model

# fintech: keyring = EbicsKeyRing(keys=tempfile_path, passphrase=conn.passphrase); ...; keyring.save()
keyring = Keyring.from_dict(json.loads(blob), "passphrase")

fake = FakeBank()   # in the app: Bank(conn.host_id, conn.ebics_url)
fake.register_download(Service.CAMT_053_DE, sample_camt053())
client = EbicsClient(fake.bank, user, keyring, transport=fake)
fake.onboard(client)
blob = json.dumps(keyring.to_dict("passphrase"))                 # write back after the session

# fintech: documents = client.C53(start=start, end=end); client.confirm_download()
documents = client.download(Service.CAMT_053_DE, start=date(2026, 10, 1), end=date(2026, 10, 31))
print(len(documents), "camt.053 file(s); parse them with your CAMT parser")
```

The camt.053 parsing that the project does with `fintech.sepa.CAMTDocument` has no equivalent
here: you receive the XML bytes.

## Documentation

- [Onboarding guide](docs/guide.md): keys, INI/HIA, letter, HPB, hashes, downloads, uploads,
  keyring storage, CA certificates and H3K for France.
- [Order types](docs/order-types.md): the Service presets and the classic order types they
  replace (C53, Z53, C52, Z52, C54, Z54, CCT, XE2, CDD and others).
- [Security notes](docs/security.md): what is verified, what is not, key storage.
- [Changelog](CHANGELOG.md), [examples](examples/).

## Security notes

The client verifies the X002 signature of every bank response and refuses downloads and uploads
until you have compared the bank key hashes with the bank's letter and set
`keyring.bank_keys_verified = True`. Uploads need `allow_uploads=True`. The keyring file is
encrypted with a passphrase, mode 600. It does not validate payment file content, bank
certificate chains, or support dual signatures. Details in [docs/security.md](docs/security.md);
report vulnerabilities privately through the
[advisory form](https://github.com/DylanMerigaud/python-ebics-client/security/advisories/new).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most useful contribution is a bank interop report.

## License

MIT, see [LICENSE](LICENSE).
