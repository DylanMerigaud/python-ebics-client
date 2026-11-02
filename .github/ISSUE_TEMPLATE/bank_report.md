---
name: Bank interop report
about: Tell us which bank and which orders worked or failed
title: "Bank report: <bank name>, <country>"
labels: bank-report
---

Version 0.1.0 is tested against the official H005 schemas and an in-process test bank, not yet
against production banks. Every report, success or failure, helps.

## Bank

- Bank name and country:
- EBICS version the bank offers (the result of `client.hev()`):
- Production or test environment:
- Certificate type (self-signed from the library, or CA-issued):

## Results

Fill one line per order you tried. Use the `Service` preset you used, or the full Service
fields if you changed it.

| Step or order | Service or order type | Worked? | Technical return code | Business return code | Notes |
|---|---|---|---|---|---|
| INI | | | | | |
| HIA (or H3K) | | | | | |
| HPB | | | | | |
| Download | | | | | |
| Upload | | | | | |

## What you had to change

<!-- For example a different msg_version, scope, container, or a bank-specific option. -->

## Before you send this

Never paste private keys, passphrases, keyring files, account numbers, IBANs, names or
statement contents. The return codes and the service fields are enough. If you attach an
XML message, remove every business value from it first.
