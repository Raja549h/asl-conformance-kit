# Security Policy

This kit is the public conformance surface of the Agent Safety Layer: the
protocol vectors, the standalone verifier that reads them, and copies of the
reports that describe how the implementation was measured. A defect here is
usually a defect in the specification the implementation is held to, so it is
worth reporting even if the ASL source tree is not part of this repository.

## Reporting a vulnerability

Please do **not** open a public issue for anything that bypasses a control —
path traversal, sandbox or confinement escape, a signature or token that
verifies when it should not, a race in the audit chain, or a vector that a
compliant implementation can be made to pass while doing the wrong thing.

Use one of these private channels:

- **E-mail:** [rajtulshan3@gmail.com](mailto:rajtulshan3@gmail.com).
- **GitHub:** *Security* → *Report a vulnerability* on this repository, which
  opens a private advisory rather than an issue.
- If private vulnerability reporting is not enabled where you are reading this,
  open an issue in the implementation repository
  ([Raja549h/helper](https://github.com/Raja549h/helper)) with the single word
  `SECURITY` in the title and **no details in the body**, and wait for a
  maintainer to move it to a private advisory. Do not describe the bypass in a
  public issue.

That address is the same maintainer the implementation repository names in its
own `SECURITY.md`, so a report about a vector, the verifier or a bundled report
reaches somebody who can fix the ASL source too. It replaced an earlier
revision of this file that deliberately named no address at all, because
`SECURITY_CONTACT_EMAIL` had not been supplied when the kit was assembled and
publishing a placeholder (as opposed to none) is worse than useless: mail sent
to one is silently lost.

## What to include

- Which repository and revision you checked (`SOURCE_COMMIT` names the
  implementation commit this kit's `conformance/` was mirrored against).
- The command you ran, in full — normally
  `python conformance/verify_vectors.py` — and its complete output.
- A proof-of-concept script, or the vector file plus the case name that behaves
  differently from what the fixtures say.
- Environment: OS, Python version, and whether ASL itself was installed. The
  verifier is standard-library only, so a bypass found here does not depend on
  the implementation being present.

## What "verified" means here

`conformance/verify_vectors.py` checks the fixtures with its own standard-library
reimplementation of the algorithms, including RFC 8032 Ed25519 verification, so
a green run is evidence that two independent implementations agree — not
evidence that the ASL implementation is secure. Receipts in
`conformance/benchmarks/receipts/` that carry only an HMAC (`v1`) can be checked
by the host that wrote them and by nobody else; receipts that carry
`receipt_ed25519` are checked against `conformance/verifier_public_key.json`,
which is the point of publishing that key. See `STATUS.md` for which of the
bundled claims were measured on a kernel rather than on a mediation layer.

## Response

We aim to respond within 48 hours and to publish a fix or an explicit statement
of the limitation within 30 days.
