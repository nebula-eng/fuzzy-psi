# Contributing

## Setup

```bash
python -m pip install -e ".[plots]"
PYTHONPATH=src python -m unittest discover -s tests -v
```

`.[plots]` is what `make figures` needs. The tests run without it.

## Design rules

These are the properties the reported results depend on. A patch that breaks one is
rejected even when the tests pass, because the tests cover only part of the space.

1. Standard library only: `hashlib`, `hmac`, `secrets`, `pow`. A patch that adds a cryptography dependency changes the premise of the project.
2. No network access beyond `127.0.0.1`. `demo` opens one loopback TCP socket and nothing else.
3. Byte counts and match counts are deterministic. Wall-clock numbers are measurements and are labelled as such wherever they appear.
4. Security is discussed as leakage, not asserted. The consistency proof's own leak is measured in `results/leakage.json`.

## Changing a reported number

Every figure and table in `README.md` and `docs/EVALUATION.md` comes from
`results/results.json`. To change a number you re-run the evaluation, commit the
regenerated file, and let the diff show what moved. Hand-editing a table is the one
change that is always rejected; `scripts/check_repro.py` exists to catch it.

## Pull requests

Say what you measured, not only what you changed. If the patch moves a reported
value, include the before and after. If it changes performance, include the command
and the machine, since that is the only way the number means anything.

## Reporting a problem

Include the command, the input, and the output. For a wrong number, name the
`results.json` field you compared against.

Security issues go through [SECURITY.md](SECURITY.md), not a public issue.

## Style

- Python 3.11+, `from __future__ import annotations`, type hints on public functions.
- Line length 110 or less. CI runs flake8 with the F-class checks only.
- ASCII in source. Documents are English.
- No runtime dependency beyond what `pyproject.toml` already declares.
