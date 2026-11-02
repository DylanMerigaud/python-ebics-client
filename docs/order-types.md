# Order types and Service presets

EBICS 3.0 (H005) replaces the many classic order types (C53, Z53, CCT, ...) with two generic
orders, **BTD** (download) and **BTU** (upload), and describes what is exchanged with a
Business Transaction Format (BTF) `Service`. `client.download(service)` sends a BTD,
`client.upload(service, data)` sends a BTU.

## Presets

`ebics_client.Service` has these presets. The values come from the Swiss Payment Standards
(Swiss Implementation Guidelines for EBICS) and from the DK (German Banking Industry
Committee) Annex 3 BTF mapping; each preset cites its source in its docstring. They have been
checked against the H005 schemas and the test bank, not yet against production banks, so
confirm them with your bank.

| Preset | Direction | ServiceName | MsgName | Scope | Option | Container | Version | Classic order type it replaces |
|---|---|---|---|---|---|---|---|---|
| `CAMT_052_CH` | download | STM | camt.052 | CH | | ZIP | 08 | Z52 (intraday report) |
| `CAMT_053_CH` | download | EOP | camt.053 | CH | | ZIP | 08 | Z53 (end of day statement) |
| `CAMT_054_CH` | download | REP | camt.054 | CH | | ZIP | 08 | Z54 (debit and credit notifications) |
| `PAIN_001_CH` | upload | MCT | pain.001 | CH | | | 09 | XE2 (credit transfer) |
| `PAIN_008_CH` | upload | SDD | pain.008 | CH | | | 08 | XE3 (direct debit) |
| `CAMT_052_DE` | download | STM | camt.052 | DE | | ZIP | | C52 (intraday report) |
| `CAMT_053_DE` | download | EOP | camt.053 | DE | | ZIP | | C53 (statement) |
| `CAMT_054_DE` | download | REP | camt.054 | DE | | ZIP | | C54 (notifications) |
| `PAIN_001_DE` | upload | SCT | pain.001 | DE | | | | CCT (SEPA credit transfer) |
| `PAIN_008_DE` | upload | SDD | pain.008 | DE | COR | | | CDD (SEPA core direct debit) |

"Version" is the `version` attribute of MsgName (`msg_version` in the dataclass). A blank
field is not sent.

## Other services and other banks

Banks publish the BTF parameters they support, and they differ: another message version,
another scope (for example a French bank), a service option, a container. Build your own
`Service` or adapt a preset:

```python
from ebics_client import Service

mine = Service.CAMT_053_CH.with_(msg_version="04")
custom = Service("EOP", "camt.053", scope="FR", container="ZIP", msg_version="02")
print(mine)
print(custom)
```

The fields are `name` (3 upper case characters), `msg_name`, `scope`, `option`, `container`
(`"ZIP"`, `"XML"` or `"SVC"`), `msg_version`, `variant` and `format`, in the order of the
`Service` element of `ebics_orders_H005.xsd`. `Service` is a frozen dataclass, so it can be
used as a dictionary key.

If a download has `container="ZIP"`, `download` unpacks it and returns one `bytes` per file in
the archive.

## Not covered

- Classic H004 order types (C53, Z53, CCT, ...) are not sent; the library speaks H005 only.
- Presets for other countries are not included. A report that gives the working BTF
  parameters for your bank lets us add one: see the bank report issue template.
- Other orders (HAA list of supported services, HTD user data, HKD, status reports) are not
  implemented in 0.1.0.
