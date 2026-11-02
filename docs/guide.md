# Onboarding a bank

This guide takes a new EBICS user from nothing to a first download. The code runs against the
test bank `ebics_client.testing.FakeBank` so you can try each step offline; for a real bank you
replace the `FakeBank` lines as described in each section.

You need from your bank: the **HostID**, the **URL** of its EBICS endpoint, your **PartnerID**
and your **UserID**. Ask the bank which EBICS version and which services (BTF order
parameters) your contract includes.

## 1. Generate the keys

An EBICS 3.0 user has three RSA keys, each with an X.509 certificate:

| Key | Use |
|---|---|
| A006 | electronic signature of uploads (RSASSA-PSS, SHA-256) |
| X002 | authentication of every `ebicsRequest` and of HPB (INI and HIA are unsecured, H3K is unsigned) |
| E002 | encryption of the order data |

```python
from ebics_client import Keyring, User

user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user, subject_country="CH")
print(keyring.signature_certificate.subject.rfc4514_string())
```

`Keyring.generate` creates 2048 bit keys and self-signed certificates (allowed in Germany and
Switzerland). Use `key_size=` for up to 4096 bits. Save the keyring at once (see
"Storing the keyring" below): the keys exist only in memory until you do.

## 2. Send INI and HIA

```python
from ebics_client import EbicsClient, Keyring, User
from ebics_client.testing import FakeBank

fake = FakeBank()
user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user)
client = EbicsClient(fake.bank, user, keyring, transport=fake)  # real bank: no transport=
client.ini()   # sends the A006 signature certificate
client.hia()   # sends the X002 and E002 certificates
```

For a real bank, build the client with `Bank(host_id="...", url="https://...")` and leave out
`transport=`: the default `HttpTransport` posts over HTTPS with `urllib`. `client.hev()` asks
the bank which EBICS versions it offers; check that `H005` is in the list before going on.

If the bank gave you CA-issued certificates (see the France section), use `client.h3k()`
instead of INI and HIA.

## 3. Print, sign and send the letter

The bank only activates your user after it has compared the certificate hashes it received with
the ones on a signed paper (or PDF) letter.

```python
from ebics_client import Bank, Keyring, User, letter

bank = Bank(host_id="EBIXHOST", url="https://ebics.example-bank.ch/ebicsweb")
user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user)
print(letter.ini_letter(bank, user, keyring))
```

`ini_letter` returns plain text with both sections (INI and HIA): your IDs, the certificate
issuer and serial, and the SHA-256 hash of each certificate. `letter.hia_letter` gives the HIA
section alone. Print it, sign it, send it to the bank by the channel the bank asks for. Some
banks want their own form with the hashes copied onto it; the hashes are what counts. Banks
usually activate the user within a few working days.

## 4. Fetch the bank keys (HPB)

Once the bank confirms the activation:

```python
from ebics_client import EbicsClient, Keyring, User
from ebics_client.testing import FakeBank

fake = FakeBank()
user = User(partner_id="PARTNER1", user_id="USER1")
client = EbicsClient(fake.bank, user, Keyring.generate(user), transport=fake)
client.ini()
client.hia()
hashes = client.hpb()
print(hashes)
```

`hpb()` downloads the bank's X002 and E002 certificates, stores them in the keyring and returns
their SHA-256 hashes as `{"X002": "1FAF 0FD5 ...", "E002": "..."}`. They are stored
**unverified**.

## 5. Compare the bank hashes and set verified

The bank publishes the hashes of its keys in a letter or on its site. Compare them, character
by character, with the output of `hpb()` (or `letter.bank_key_hashes(keyring)`). Do this over a
channel different from the one that carried the HPB request: that comparison is what protects
you from someone answering in the bank's place.

When they match:

```python
from ebics_client import EbicsClient, Keyring, User
from ebics_client.testing import FakeBank

fake = FakeBank()
user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user)
client = EbicsClient(fake.bank, user, keyring, transport=fake)
client.ini()
client.hia()
hashes = client.hpb()
if hashes == fake.key_hashes():  # real bank: compare with the bank's letter
    keyring.bank_keys_verified = True
print(keyring.bank_keys_verified)
```

Until `keyring.bank_keys_verified` is `True`, `download` and `upload` raise
`BankKeysNotVerified`. Fetching the same certificates again keeps the flag; new certificates
reset it. Save the keyring after setting the flag.

## 6. Download

```python
from datetime import date

from ebics_client import EbicsClient, Keyring, Service, User
from ebics_client.testing import FakeBank, sample_camt053

fake = FakeBank()
fake.register_download(Service.CAMT_053_CH, sample_camt053())
user = User(partner_id="PARTNER1", user_id="USER1")
client = EbicsClient(fake.bank, user, Keyring.generate(user), transport=fake)
fake.onboard(client)
files = client.download(Service.CAMT_053_CH, start=date(2026, 10, 1), end=date(2026, 10, 31))
print(len(files), "file(s)")
```

`download` returns the bytes of each file, with ZIP containers unpacked (`unzip=False` returns
the ZIP as one item). Without `start` and `end` the bank sends what is new. When nothing is
available the bank answers 090005 and the client raises `NoDownloadData`. The client
acknowledges the download (receipt) only after decrypting and unpacking it; on failure the
bank keeps the data. Pick the `Service` from [order-types.md](order-types.md) or change one
with `Service.with_(...)`.

## Uploads (allow_uploads)

An upload can move money, so the client refuses it by default:

```python
from ebics_client import EbicsClient, Keyring, Service, UploadsDisabled, User
from ebics_client.testing import FakeBank

fake = FakeBank()
user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user)
read_only = EbicsClient(fake.bank, user, keyring, transport=fake)
fake.onboard(read_only)
try:
    read_only.upload(Service.PAIN_001_CH, b"<Document/>")
except UploadsDisabled:
    print("refused: allow_uploads is off")

client = EbicsClient(fake.bank, user, keyring, transport=fake, allow_uploads=True)
print("order id:", client.upload(Service.PAIN_001_CH, b"<Document/>"))
```

`upload` compresses, signs (A006) and encrypts the data, sends it in segments, and returns the
order id. CR, LF and Ctrl-Z are removed from the order data before signing, as EBICS banks do
when they hash it, and the signature, the `DataDigest` and the encrypted payload all cover that
one normalized document, so the file the bank receives has no line breaks. Your bank must have given your user the right to sign the order type (signature
class, and a second signer if the bank requires one). The library signs with your A006 key
only; a dual-signature workflow is not part of version 0.1.0. Test with a small file and the
bank's test environment first.

## Storing the keyring

```python
import os
import tempfile

from ebics_client import Keyring, User

user = User(partner_id="PARTNER1", user_id="USER1")
keyring = Keyring.generate(user)
path = os.path.join(tempfile.mkdtemp(), "keys.json")
keyring.save(path, passphrase="a long passphrase")
restored = Keyring.load(path, passphrase="a long passphrase")
print(restored.signature_certificate == keyring.signature_certificate)
```

The file is JSON; the three private keys are PKCS#8 PEM encrypted with the passphrase
(`BestAvailableEncryption`) and the file mode is 600. The certificates and the bank
certificates are not secret. A wrong passphrase raises `KeyringError`.

To keep the keyring in a database instead of a file, use `keyring.to_dict(passphrase)` and
`Keyring.from_dict(data, passphrase)`: the dict is JSON-ready.

Back up the keyring. Losing the keys means a new INI and HIA and a new letter.

## CA certificates and H3K (France)

French banks usually require certificates issued by a certification authority instead of
self-signed ones, and the keys are sent with H3K, one request carrying all three
certificates. Create the keys, have the certificates issued for each public key, then load
them:

```python
keyring.load_certificate("A006", open("a006.pem", "rb").read())   # PEM or DER
keyring.load_certificate("X002", open("x002.pem", "rb").read())
keyring.load_certificate("E002", open("e002.pem", "rb").read())
client.h3k()
client.hpb()
```

`load_certificate` checks that the certificate carries the matching key and raises
`KeyringError` otherwise. Your CA will want a certificate signing request per key; the library
does not create CSRs in 0.1.0, use `openssl` or your CA's tool with the private keys exported
from the keyring. Whether the bank still wants the paper letter with H3K depends on the bank:
ask. Then continue with HPB and the hash comparison as above.

## When something fails

Errors derive from `EbicsError` with the return `code` and `text`: `EbicsTechnicalError`
(header code), `EbicsBusinessError` (body code), `NoDownloadData` (090005),
`BankKeysNotVerified`, `UploadsDisabled`, `SignatureInvalid` (the bank's response signature or
the HPB checks failed) and `KeyringError`. Quote the codes when you report a problem; see the
bank report template in `.github/ISSUE_TEMPLATE/`.
