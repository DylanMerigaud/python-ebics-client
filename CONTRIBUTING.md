# Contributing

## Development setup

```
git clone https://github.com/DylanMerigaud/python-ebics-client
cd python-ebics-client
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Python 3.9 or newer. The runtime dependencies are `cryptography` and `lxml`; keep it that way.

## Checks

Run these before sending a pull request. CI runs the same on Python 3.9 to 3.13.

```
.venv/bin/ruff check .
.venv/bin/mypy ebics_client
.venv/bin/python -m pytest -q
```

New behaviour comes with a test. Keep public functions and methods fully annotated.

## XSD validation

The official EBICS H005 schemas are vendored in `tests/xsd/H005/`. The tests validate every
request the library builds and every response `FakeBank` builds against `ebics_H005.xsd`
(helper `assert_valid` in `tests/conftest.py`). A change to a request builder must keep that
validation green; do not loosen the schemas.

## Bank interop results

The most useful contribution is a report from a real bank. Open an issue with the
"Bank interop report" template: bank name and country, what you ran (INI, HIA or H3K, HPB,
downloads, uploads), the `Service` fields, and the technical and business return codes.
Failures are as useful as successes. Never paste private keys, passphrases, keyring files,
account numbers or statement contents. If a bank needs a different `Service` (another
`msg_version`, `scope`, `option` or `container`), say which, so a preset can be added.

## Security reporting

Do not open a public issue for a vulnerability. Use the private advisory form of the
repository: <https://github.com/DylanMerigaud/python-ebics-client/security/advisories/new>.
Include the version, a description and, if you can, a minimal reproduction without real keys.

## License

By contributing you agree that your contribution is licensed under the MIT license.
