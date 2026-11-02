# Security notes

Version 0.1.0 is alpha, tested against the official H005 schemas and an in-process test bank,
not yet against a production bank. Read this page before pointing it at real accounts.

## What the library verifies

- **Bank response signature.** Every `ebicsResponse` carries an X002 signature of the bank. The
  client verifies it with the bank's X002 key from the keyring and raises `SignatureInvalid`
  when it does not match, including when an authenticated element was changed.
- **Encryption target.** Encrypted answers (HPB, downloads) state the digest of the E002 key
  they were encrypted for; the client checks it is ours before decrypting.
- **HPB host.** The HostID in the HPB answer must equal the HostID configured.
- **Key sizes.** Keys and certificates outside 2048 to 4096 bits RSA are refused.
- **Segment order and transaction.** Download segments must arrive in order and belong to the
  same transaction.
- **Download acknowledgement.** The bank gets a positive receipt only after the data was
  decrypted and unpacked.
- **Transport.** The default `HttpTransport` refuses non-HTTPS URLs (unless
  `allow_insecure_http=True`), uses the certificate validation of the Python `ssl` module and
  refuses answers larger than `max_response_bytes` (default 64 MiB).
- **Compressed data.** Truncated zlib data and bytes after the zlib stream are refused.
- **ZIP containers.** An archive that unpacks to more than 1 GiB, or that cannot be unpacked
  (bad CRC, unsupported compression, encrypted entry), is refused with a negative receipt. XML is parsed
  without entity resolution or network access.
- **Defaults that protect you.** Uploads raise `UploadsDisabled` unless `allow_uploads=True`.
  Downloads and uploads raise `BankKeysNotVerified` until you set
  `keyring.bank_keys_verified = True`.

## What it does not verify

- **The bank's identity on first contact.** HPB answers are not signed. Trust in the bank keys
  comes only from your comparison of their hashes with the bank's own letter. Skipping that
  comparison (or setting the flag without doing it) removes the protection. Do the comparison
  on a channel other than the EBICS connection.
- **Certificate chains and validity.** The bank's certificates are pinned by hash comparison;
  their validity period and issuer are not checked.
- **The business content.** The camt and pain files are passed through as bytes. The library
  does not validate them against the ISO 20022 schemas, parse them, or check amounts or
  accounts. Validate and review payment files before uploading.
- **Dual signatures.** Uploads carry one A006 signature, the user's. Banks that require a
  second signer need the second signature through their own channel.
- **Production banks.** No claim is made that a given bank accepts the requests. Report your
  results with the bank report template.
- **Side channels and memory.** Keys are held as Python objects in memory; the library does not
  lock or wipe memory.

## Key storage

- `Keyring.save(path, passphrase)` writes JSON, with the three private keys as PKCS#8 PEM
  encrypted by `BestAvailableEncryption` and the file mode 600. An empty passphrase is refused.
- Choose a long random passphrase and keep it out of the repository, the environment of other
  users, and the keyring file's folder. The passphrase protects the keys at rest; anyone with
  the file and the passphrase can sign in your name.
- Do not commit keyring files. Do not paste them in issues.
- `to_dict` and `from_dict` let you keep the keyring in a database; the same encryption
  applies. Restrict access to that table.
- The A006 key signs payments. If you suspect it leaked, tell the bank at once to block the
  user, then generate new keys and onboard again.
- Keep a backup of the keyring in a second protected place. Without it you must onboard again.

## Reporting a vulnerability

Use the private advisory form: <https://github.com/DylanMerigaud/python-ebics-client/security/advisories/new>.
