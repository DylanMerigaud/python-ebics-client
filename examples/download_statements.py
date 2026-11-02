"""Download camt.053 bank statements, offline, against the in-process FakeBank.

Run it with: python examples/download_statements.py

To point it at a real bank, replace the FakeBank lines:

    bank = Bank(host_id="YOURHOSTID", url="https://ebics.your-bank.example/ebicsweb")
    keyring = Keyring.load("keys.json", passphrase="...")   # onboarded, see onboard_bank.py
    client = EbicsClient(bank, user, keyring)               # default transport: HttpTransport

and drop the fake.register_download(...) and fake.onboard(...) lines. Use the Service
preset your bank documents (Service.CAMT_053_CH, Service.CAMT_053_DE, ...).
"""

from __future__ import annotations

from datetime import date

from lxml import etree

from ebics_client import EbicsClient, Keyring, NoDownloadData, Service, User
from ebics_client.testing import FakeBank, sample_camt053


def main() -> None:
    fake = FakeBank()
    fake.register_download(Service.CAMT_053_CH, sample_camt053())

    user = User(partner_id="PARTNER1", user_id="USER1")
    client = EbicsClient(fake.bank, user, Keyring.generate(user), transport=fake)
    fake.onboard(client)  # INI, HIA, HPB and the key check; see onboard_bank.py

    statements = client.download(
        Service.CAMT_053_CH, start=date(2026, 10, 1), end=date(2026, 10, 31)
    )
    ns = {"c": "urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"}
    for number, statement in enumerate(statements, start=1):
        root = etree.fromstring(statement)
        entries = root.findall(".//c:Ntry", ns)
        print(f"file {number}: {len(statement)} bytes, {len(entries)} entries")

    try:
        client.download(Service.CAMT_053_CH)  # nothing new is left
    except NoDownloadData:
        print("no further statements available")


if __name__ == "__main__":
    main()
