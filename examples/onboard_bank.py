"""Onboard a new EBICS user, offline, against the in-process FakeBank.

Run it with: python examples/onboard_bank.py

The steps are the ones a real bank needs:
  1. generate the keys and self-signed certificates,
  2. send them with INI and HIA,
  3. print the letter, sign it and send it to the bank,
  4. after the bank activates the user, fetch its keys with HPB,
  5. compare the bank key hashes with the ones the bank sent you, then mark them verified.

To point it at a real bank, replace the FakeBank lines with
    bank = Bank(host_id="YOURHOSTID", url="https://ebics.your-bank.example/ebicsweb")
and the default transport (leave out transport=). Steps 1 to 3 run on day one; steps 4 and 5
run once the bank confirms the activation. Save the keyring between the two sessions.
In step 5 compare with the bank's own letter instead of fake.key_hashes().
"""

from __future__ import annotations

import os
import tempfile

from ebics_client import EbicsClient, Keyring, User, letter
from ebics_client.testing import FakeBank


def main() -> None:
    fake = FakeBank()
    user = User(partner_id="PARTNER1", user_id="USER1")
    keyring = Keyring.generate(user, subject_country="CH")
    client = EbicsClient(fake.bank, user, keyring, transport=fake)

    print("bank supports:", [(v.protocol, v.version) for v in client.hev()])
    client.ini()
    client.hia()
    print(letter.ini_letter(fake.bank, user, keyring))  # print, sign, send to the bank

    # ... the bank activates the user ...
    hashes = client.hpb()
    print("bank key hashes:", hashes)
    if hashes == fake.key_hashes():  # with a real bank: compare with the bank's letter
        keyring.bank_keys_verified = True

    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "keys.json")
        keyring.save(path, passphrase="change-me")
        restored = Keyring.load(path, passphrase="change-me")
    print("verified after reload:", restored.bank_keys_verified)


if __name__ == "__main__":
    main()
