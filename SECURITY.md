# Security policy

## Reporting a vulnerability

Report privately through GitHub's [security advisory
form](https://github.com/nebula-eng/fuzzy-psi/security/advisories/new). The
report is visible only to the maintainer. There is no mailing list, so nothing sent
to an address at this project's name reaches anyone.

Include the command you ran, the input that triggers the problem, and the Python
version. You will get an acknowledgement within 72 hours.

## What counts here

This project runs a two-party protocol that finds near-duplicate indicators across two sets, using LSH banding, Diffie-Hellman PSI, and a batched proof that the client used one exponent for its whole submission. That shapes what a vulnerability is:

- Semi-honest server and malicious client for the consistency property. A malicious server is out of scope and discussed in `docs/THREAT_MODEL.md`.
- The consistency proof needs the bases published, which lets the server enumerate the 12-bit band-key space. This is measured, not waved away.
- 2048-bit MODP is correct but 6-8x larger and 10-50x slower than an elliptic-curve instantiation. Not audited, not constant-time, not suitable for deployment.

A wrong verdict with no crash is in scope. In a measurement artifact a silently wrong
number is worse than an exception, because nothing prompts a reader to check it.

## Out of scope

- Anything that requires modifying the repository before running it.
- Differences caused by the host, where the README already states that a number is
  machine-dependent.
- The limits listed under Limitations in the README. They are known and written
  down; a report that restates one is not a finding.

## Data handling

Set elements are synthetic indicators generated from a seed. `demo` exchanges blinded group elements over loopback TCP.
