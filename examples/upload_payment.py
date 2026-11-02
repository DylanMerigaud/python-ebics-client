"""Upload a pain.001 credit transfer file, offline, against the in-process FakeBank.

Run it with: python examples/upload_payment.py

Uploads can move money, so the client refuses them unless allow_uploads=True. To point
this at a real bank, replace the FakeBank lines with a Bank(host_id=..., url=...), a keyring
loaded with Keyring.load(...) after onboarding (see onboard_bank.py) and the default
transport, and pass your own pain.001 bytes. Test with a small payment first.
"""

from __future__ import annotations

from ebics_client import EbicsClient, Keyring, Service, UploadsDisabled, User
from ebics_client.testing import FakeBank

# A placeholder: use a complete pain.001 file from your accounting system.
PAIN_001 = b"""<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09">
  <CstmrCdtTrfInitn>
    <GrpHdr><MsgId>EXAMPLE-0001</MsgId></GrpHdr>
  </CstmrCdtTrfInitn>
</Document>
"""


def main() -> None:
    fake = FakeBank()
    user = User(partner_id="PARTNER1", user_id="USER1")
    keyring = Keyring.generate(user, subject_country="CH")

    read_only = EbicsClient(fake.bank, user, keyring, transport=fake)
    fake.onboard(read_only)
    try:
        read_only.upload(Service.PAIN_001_CH, PAIN_001)
    except UploadsDisabled as error:
        print("default client:", error.text)

    client = EbicsClient(fake.bank, user, keyring, transport=fake, allow_uploads=True)
    order_id = client.upload(Service.PAIN_001_CH, PAIN_001, file_name="payments.xml")
    received = fake.uploads[-1]
    print("order id:", order_id)
    print("bank got", len(received.data), "bytes; A006 verified:", received.signature_verified)


if __name__ == "__main__":
    main()
