"""Standalone conformance verifier.

Reads ``conformance/vectors/*.json`` and checks every case using only the
standard library -- no ``asl`` imports, no network. A future Rust or
verified-kernel port must reproduce these exact bytes: HMAC-SHA256 over the
canonical JSON form (sorted keys, fixed separators, ensure_ascii=False,
UTF-8, no NaN/Infinity/duplicate keys).

Run::

    python conformance/verify_vectors.py
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VECTORS = REPO / "conformance" / "vectors"

#: The size of a complete vector set, counted per case.
#:
#: This is a gate, not a caption. Without it a fixture directory that had
#: quietly lost a file -- or a case -- reported "0 failures" and exit code 0,
#: because the only number the verifier had was the one it had just counted.
#: It is compared with an ``if``/``sys.exit`` and never an ``assert``: ``python
#: -O`` deletes assert statements, and an optimised CI job would then skip the
#: accounting and still pass.
EXPECTED_VECTORS = 45

# The single enabled algorithm, exactly as the trusted core declares it.
ALGORITHM_ID = "HS256"
FORMAT_VERSION = 1

# Clearly-labeled FAKE test key. Never a production key.
FAKE_KEY_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
FAKE_KEY = bytes.fromhex(FAKE_KEY_HEX)


class VectorError(Exception):
    pass


# ── canonical JSON (independent reimplementation of asl.core.canonical) ──


def _check(value, depth=0):
    if depth > 64:
        raise VectorError("value nests too deeply")
    if value is None or value is True or value is False:
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise VectorError("string is not valid UTF-8") from exc
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise VectorError("NaN and Infinity are not allowed")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise VectorError("object keys must be strings")
            _check(item, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check(item, depth + 1)
        return
    raise VectorError(f"unsupported type: {type(value).__name__}")


def canonical_json(value) -> str:
    _check(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def canonical_bytes(value) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_hash(value) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def parse_strict(text):
    """Parse JSON refusing duplicate keys, NaN/Infinity, lone surrogates."""

    def no_dupes(pairs):
        seen = {}
        for key, value in pairs:
            if key in seen:
                raise VectorError(f"duplicate key: {key!r}")
            seen[key] = value
        return seen

    def reject_constant(name):
        raise VectorError(f"constant {name} is not allowed")

    value = json.loads(text, object_pairs_hook=no_dupes, parse_constant=reject_constant)
    _check(value)
    return value


def parse_strict_or_error(text):
    """Like parse_strict, but turns any JSON error into a VectorError."""
    try:
        return parse_strict(text)
    except VectorError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise VectorError(f"invalid JSON: {exc}") from exc


# ── key id ──


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


EXPECTED_KEY_ID = key_id(FAKE_KEY)


# ── verifiers ──


def verify_canonical(case) -> None:
    text = case["input"]
    op = case.get("op", "encode")
    if op == "parse":
        try:
            parse_strict_or_error(text)
        except VectorError as exc:
            if case.get("error") and case["error"] in str(exc):
                return
            raise VectorError(f"expected '{case['error']}', got {exc}") from exc
        raise VectorError("expected a rejection but parsing succeeded")
    expected = case["expected"]
    actual = canonical_json(case["input"])
    if actual != expected:
        raise VectorError(f"canonical mismatch: got {actual!r} expected {expected!r}")


def verify_hashing(case) -> None:
    actual = canonical_hash(case["input"])
    if actual != case["expected"]:
        raise VectorError(f"hash mismatch: got {actual} expected {case['expected']}")


def _token_body(wire):
    parts = wire.split(".")
    if len(parts) != 2:
        raise VectorError("token must have exactly two parts")
    body_b64, signature = parts
    if len(signature) != 64:
        raise VectorError("signature must be 64 hex chars")
    raw = base64.b64decode(body_b64 + "=" * (-len(body_b64) % 4), altchars=b"-_", validate=True)
    payload = parse_strict(raw.decode("utf-8"))
    return payload, signature


def verify_token(case) -> None:
    wire = case["wire"]
    expect = case["expect"]
    payload, signature = _token_body(wire)

    required = {
        "version",
        "algorithm_id",
        "key_id",
        "agent_id",
        "run_id",
        "action",
        "args_hash",
        "issued_at",
        "expires_at",
        "nonce",
    }
    if set(payload) != required:
        raise VectorError(f"token fields {set(payload)} != {required}")

    if not isinstance(payload["version"], int) or isinstance(payload["version"], bool):
        raise VectorError("version must be an integer")
    if payload["version"] != FORMAT_VERSION:
        if expect == "ok":
            raise VectorError(f"unsupported version {payload['version']}")
        return  # deny is correct

    if payload["algorithm_id"] != ALGORITHM_ID:
        if expect == "ok":
            raise VectorError(f"unsupported algorithm {payload['algorithm_id']}")
        return

    if payload["key_id"] != EXPECTED_KEY_ID:
        if expect == "ok":
            raise VectorError(f"wrong key id {payload['key_id']}")
        return

    body = canonical_bytes(payload)
    expected_sig = hmac.new(FAKE_KEY, body, hashlib.sha256).hexdigest()
    ok = hmac.compare_digest(expected_sig, signature)

    if expect == "ok" and not ok:
        raise VectorError("valid token failed to verify")
    if expect == "deny" and ok:
        raise VectorError("a denied token verified (fail-open!)")


def verify_audit_entry(entry, prev_hash, key) -> None:
    required = {
        "seq",
        "timestamp",
        "event",
        "data",
        "prev_hash",
        "version",
        "algorithm_id",
        "key_id",
        "hash",
    }
    if set(entry) != required:
        raise VectorError(f"audit entry fields {set(entry)} != {required}")
    if entry["prev_hash"] != prev_hash:
        raise VectorError("audit prev_hash does not chain")
    if entry["version"] != FORMAT_VERSION:
        raise VectorError("unsupported audit version")
    if entry["algorithm_id"] != ALGORITHM_ID:
        raise VectorError("unsupported audit algorithm")
    if entry["key_id"] != EXPECTED_KEY_ID:
        raise VectorError("audit key id mismatch")
    body = {
        k: entry[k]
        for k in (
            "seq",
            "timestamp",
            "event",
            "data",
            "prev_hash",
            "version",
            "algorithm_id",
            "key_id",
        )
    }
    computed = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(computed, entry["hash"]):
        raise VectorError("audit entry hash does not verify")


def verify_audit(doc) -> None:
    key = FAKE_KEY
    prev = doc["genesis_hash"]
    for entry in doc["entries"]:
        verify_audit_entry(entry, prev, key)
        prev = entry["hash"]
    cp = doc["checkpoint"]
    cp_payload = {k: cp[k] for k in ("count", "head_hash", "algorithm_id", "key_id")}
    if cp["head_hash"] != prev:
        raise VectorError("checkpoint head_hash does not match chain head")
    expected_hmac = hmac.new(key, canonical_bytes(cp_payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hmac, cp["hmac"]):
        raise VectorError("checkpoint hmac does not verify")


def verify_attestation(case) -> None:
    """Verify an attestation wire token against the FAKE test key."""
    wire = case["wire"]

    parts = wire.split(".")
    if len(parts) != 2:
        raise VectorError("attestation must have exactly two parts")
    body_b64, signature = parts
    if len(signature) != 64:
        raise VectorError("attestation signature must be 64 hex characters")
    try:
        raw = base64.b64decode(body_b64 + "=" * (-len(body_b64) % 4), altchars=b"-_", validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise VectorError(f"attestation payload is not decodable: {exc}") from exc
    try:
        payload = parse_strict(text)
    except VectorError as exc:
        raise VectorError(f"attestation payload is not canonical JSON: {exc}") from exc

    required = {
        "version",
        "algorithm_id",
        "key_id",
        "run_id",
        "backend_class",
        "policy_hash",
        "audit_head_hash",
        "issued_at",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise VectorError("attestation payload has the wrong fields")
    if not isinstance(payload["version"], int) or isinstance(payload["version"], bool):
        raise VectorError("attestation version must be an integer")
    if payload["version"] != 1:
        raise VectorError(f"unsupported attestation version {payload['version']!r}")
    if payload["algorithm_id"] != "HS256":
        raise VectorError(f"unsupported attestation algorithm {payload['algorithm_id']!r}")
    if payload["key_id"] != EXPECTED_KEY_ID:
        raise VectorError(f"attestation key id mismatch: {payload['key_id']!r}")
    if not isinstance(payload["run_id"], str) or not payload["run_id"]:
        raise VectorError("attestation run_id must be a non-empty string")

    # Verify HMAC signature.
    body = canonical_bytes(payload)
    expected_sig = hmac.new(FAKE_KEY, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, signature):
        raise VectorError("attestation signature does not verify")


# ── boundary wire contracts (P9) ────────────────────────────────────────

WITNESS_SCHEMA = "asl.witness.v1"
HW_KILL_SCHEMA = "asl.hw_kill.v1"
BOUNDARY_VERSION = 1
BOUNDARY_ALGORITHM_ID = "HS256"

WITNESS_FIELDS = frozenset(
    {
        "schema",
        "version",
        "algorithm_id",
        "run_id",
        "seq_no",
        "audit_head_hash",
        "policy_hash",
        "timestamp_ns",
        "host_hmac",
    }
)
HW_KILL_FIELDS = frozenset(
    {
        "schema",
        "version",
        "algorithm_id",
        "target_node_id",
        "reason_code",
        "monotonic_nonce",
        "audit_head_hash",
        "hmac_sig",
    }
)
KILL_REASON_CODES = frozenset(
    {
        "policy_violation",
        "lease_expired",
        "budget_exhausted",
        "human_switch",
        "tripwire_freeze",
        "witness_disagreement",
    }
)


def _boundary_parse(wire) -> dict:
    """Strict JSON: duplicate keys and non-finite numbers are refused."""

    def _no_duplicates(pairs):
        seen = {}
        for key, value in pairs:
            if key in seen:
                raise VectorError(f"duplicate key {key!r}")
            seen[key] = value
        return seen

    def _no_constants(token):
        raise VectorError(f"non-finite number {token!r}")

    try:
        return json.loads(wire, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except json.JSONDecodeError as exc:
        raise VectorError(f"not JSON: {exc}") from exc


def _boundary_body(payload: dict, signature_field: str) -> dict:
    return {key: value for key, value in payload.items() if key != signature_field}


def verify_boundary_case(case) -> None:
    """Verify one external-boundary wire case against the FAKE test key.

    Negative cases are part of the vectors on purpose: a verifier that only ever
    sees well-formed packets has not been shown to reject anything.
    """
    signature_field = "host_hmac" if case["kind"] == "witness" else "hmac_sig"
    expected_fields = WITNESS_FIELDS if case["kind"] == "witness" else HW_KILL_FIELDS
    expected_schema = WITNESS_SCHEMA if case["kind"] == "witness" else HW_KILL_SCHEMA

    expect = case.get("expect", "ok")
    try:
        payload = _boundary_parse(case["wire"])
        if not isinstance(payload, dict):
            raise VectorError("packet must be an object")
        missing = expected_fields - set(payload)
        extra = set(payload) - expected_fields
        if missing:
            raise VectorError(f"packet is missing {sorted(missing)}")
        if extra:
            raise VectorError(f"packet carries unexpected fields {sorted(extra)}")
        if payload["schema"] != expected_schema:
            raise VectorError(f"unknown schema {payload['schema']!r}")
        if payload["version"] != BOUNDARY_VERSION:
            raise VectorError(f"unsupported version {payload['version']!r}")
        if payload["algorithm_id"] != BOUNDARY_ALGORITHM_ID:
            raise VectorError(f"unsupported algorithm {payload['algorithm_id']!r}")
        for name in ("audit_head_hash",) + (("policy_hash",) if case["kind"] == "witness" else ()):
            value = payload[name]
            if not isinstance(value, str) or len(value) != 64:
                raise VectorError(f"{name} must be 64 hex characters")
            int(value, 16)
        signature = payload[signature_field]
        if not isinstance(signature, str) or len(signature) != 64:
            raise VectorError(f"{signature_field} must be 64 hex characters")
        expected_sig = hmac.new(
            FAKE_KEY, canonical_bytes(_boundary_body(payload, signature_field)), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_sig, signature):
            raise VectorError(f"{signature_field} does not verify")
        if case["kind"] == "hw_kill":
            if payload["reason_code"] not in KILL_REASON_CODES:
                raise VectorError(f"unknown reason_code {payload['reason_code']!r}")
            nonce = payload["monotonic_nonce"]
            if not isinstance(nonce, int) or isinstance(nonce, bool) or nonce < 1:
                raise VectorError("monotonic_nonce must be a positive integer")
            highest = case.get("ledger", {}).get(payload["target_node_id"], 0)
            if nonce <= highest:
                raise VectorError(
                    f"replay: nonce {nonce} is not above the ledger high-water mark {highest}"
                )
    except VectorError as exc:
        if expect == "error":
            wanted = case.get("reason")
            if wanted and wanted.lower() not in str(exc).lower():
                raise VectorError(
                    f"rejected for the wrong reason: wanted {wanted!r}, got {exc}"
                ) from exc
            return
        raise

    if expect == "error":
        raise VectorError("a packet that must be rejected was accepted")


# ── Ed25519 (RFC 8032), verification only, standard library only ───────────
#
# The same maths as ``scripts/verify_report.py`` and deliberately independent of
# the ``cryptography`` provider the product signs with: the point of a
# standalone verifier is that two implementations must agree before a receipt is
# called good.

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)

#: Domain separation: a receipt signature is never a report or token signature.
RECEIPT_DOMAIN = b"ASL-RECEIPT\x00Ed25519\x00"
RECEIPT_ED25519_FIELD = "receipt_ed25519"
RECEIPT_ED25519_KEY_ID_FIELD = "receipt_ed25519_key_id"
RECEIPT_FORMAT_VERSION = 2
ALGORITHM_ED25519 = "Ed25519"
#: The public half of the key that signs published receipts, shipped with the kit.
VERIFIER_PUBLIC_KEY = REPO / "conformance" / "verifier_public_key.json"
RECEIPTS = REPO / "conformance" / "benchmarks" / "receipts"
_B64URL = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if x % 2:
        x = _P - x
    return x


def _base_point() -> tuple[int, int, int, int]:
    by = 4 * pow(5, _P - 2, _P) % _P
    bx = _x_recover(by)
    return (bx, by, 1, bx * by % _P)


def _add(p, q):
    """Extended homogeneous coordinates: (X, Y, Z, T) with x = X/Z, y = Y/Z."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(p, scalar: int):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, p)
        p = _add(p, p)
        scalar >>= 1
    return result


def _equal(p, q) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (
        p[1] * q[2] - q[1] * p[2]
    ) % _P == 0


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True only when ``signature`` verifies over ``message`` under the key."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    encoded_a = int.from_bytes(public_key, "little")
    sign_bit = encoded_a >> 255
    a_y = encoded_a & ((1 << 255) - 1)
    if a_y >= _P:
        return False
    a_x = _x_recover(a_y)
    if (a_x & 1) != sign_bit:
        a_x = _P - a_x
    point_a = (a_x, a_y, 1, a_x * a_y % _P)
    # A non-prime-order point must not be accepted as a key.
    if not _equal(_multiply(point_a, _L), (0, 1, 1, 0)):
        return False
    r_encoded = int.from_bytes(signature[:32], "little")
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    r_sign = r_encoded >> 255
    r_y = r_encoded & ((1 << 255) - 1)
    if r_y >= _P:
        return False
    r_x = _x_recover(r_y)
    if (r_x & 1) != r_sign:
        r_x = _P - r_x
    point_r = (r_x, r_y, 1, r_x * r_y % _P)
    # RFC 8032 reduces the *whole* 64-byte digest modulo L; truncating the
    # digest first produces a different scalar and every signature fails.
    digest = hashlib.sha512(signature[:32] + public_key + message).digest()
    k = int.from_bytes(digest, "little") % _L
    return _equal(_multiply(_base_point(), s), _add(point_r, _multiply(point_a, k)))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str, *, expected_bytes: int | None = None) -> bytes:
    """Strict, unpadded base64url. Non-canonical input is refused, not repaired."""
    if not isinstance(text, str) or not text:
        raise VectorError("encoded value must be a non-empty string")
    if any(ch not in _B64URL for ch in text):
        raise VectorError("encoded value is not base64url")
    try:
        raw = base64.b64decode(
            text + "=" * (-len(text) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise VectorError(f"encoded value is not decodable: {exc}") from exc
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise VectorError(f"expected {expected_bytes} bytes, decoded {len(raw)}")
    if b64url_encode(raw) != text:
        raise VectorError("encoded value is not canonical base64url")
    return raw


def public_key_id(public_key: bytes) -> str:
    """The non-secret name of a key: first 16 hex characters of its SHA-256."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise VectorError("an Ed25519 public key is exactly 32 bytes")
    return hashlib.sha256(bytes(public_key)).hexdigest()[:16]


def load_verifier_public_key(path: Path = VERIFIER_PUBLIC_KEY) -> bytes:
    """Read the published verifier key and check it names itself honestly."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise VectorError(f"{Path(path).name} is unreadable ({exc.strerror or exc})") from exc
    except ValueError as exc:
        raise VectorError(f"{Path(path).name} is not valid JSON ({exc})") from exc
    if not isinstance(document, dict):
        raise VectorError(f"{Path(path).name} must contain a JSON object")
    if document.get("algorithm_id") != ALGORITHM_ED25519:
        raise VectorError(f"{Path(path).name} is not an {ALGORITHM_ED25519} key")
    if document.get("version") != 1:
        raise VectorError(f"{Path(path).name} has an unsupported version")
    public_key = b64url_decode(document.get("public_key_b64", ""), expected_bytes=32)
    if document.get("key_id") != public_key_id(public_key):
        raise VectorError(f"{Path(path).name} key id does not match its public key")
    return public_key


def verify_receipt(receipt: dict, *, public_key: bytes | None = None) -> list[str]:
    """Every reason this receipt's Ed25519 signature is not good, as text.

    An empty list means the signature verified; it does not mean the receipt is
    true. A v1 receipt (HMAC only, no ``receipt_ed25519``) has nothing here for
    a public verifier to check and returns no problems -- the caller says so out
    loud rather than counting it as verified.
    """
    if not isinstance(receipt, dict):
        return ["receipt must be a JSON object"]
    signature = receipt.get(RECEIPT_ED25519_FIELD)
    if signature is None:
        if RECEIPT_ED25519_KEY_ID_FIELD in receipt:
            return [f"{RECEIPT_ED25519_KEY_ID_FIELD} is present without a signature"]
        return []
    if public_key is None:
        return [
            f"{RECEIPT_ED25519_FIELD} is present but no verifier key is published "
            f"(conformance/{VERIFIER_PUBLIC_KEY.name})"
        ]
    if receipt.get("receipt_format_version") != RECEIPT_FORMAT_VERSION:
        return [
            f"receipt_format_version {receipt.get('receipt_format_version')!r} "
            f"is not the version that carries an Ed25519 signature "
            f"({RECEIPT_FORMAT_VERSION})"
        ]
    key_id = receipt.get(RECEIPT_ED25519_KEY_ID_FIELD)
    if not isinstance(key_id, str) or not key_id:
        return [f"{RECEIPT_ED25519_KEY_ID_FIELD} must be a non-empty string"]
    try:
        if key_id != public_key_id(public_key):
            return [
                f"{RECEIPT_ED25519_KEY_ID_FIELD} {key_id!r} does not name the published "
                f"verifier key {public_key_id(public_key)!r}"
            ]
    except VectorError as exc:
        return [f"{RECEIPT_ED25519_KEY_ID_FIELD} unusable: {exc}"]
    try:
        raw = b64url_decode(signature, expected_bytes=64)
    except VectorError as exc:
        return [f"{RECEIPT_ED25519_FIELD} is malformed: {exc}"]
    body = {k: v for k, v in receipt.items() if k != RECEIPT_ED25519_FIELD}
    if not ed25519_verify(public_key, RECEIPT_DOMAIN + canonical_bytes(body), raw):
        return [f"{RECEIPT_ED25519_FIELD} does not verify under the published key"]
    return []


FAMILIES = {
    "canonical.json": verify_canonical,
    "hashing.json": verify_hashing,
    "tokens.json": verify_token,
    "audit.json": verify_audit,
    "attestation_v1.json": verify_attestation,
    "boundary_v1.json": verify_boundary_case,
}

#: Families whose document is a list of cases, versus the one whose document
#: *is* the case (the audit chain).
CASE_FAMILIES = frozenset(
    {
        "canonical-json",
        "argument-hashing",
        "token-mint-verify",
        "attestation-v1",
        "boundary-wire-v1",
    }
)
CHAIN_FAMILY = "audit-chain"


def load_vector_file(path: Path) -> dict:
    """Read one vector file, refusing a fixture the verifier cannot check.

    A malformed vector document is a verdict with the file's name on it, not a
    traceback. Fail-closed: an unreadable file, invalid JSON, a non-object, a
    missing ``family``, a case list that is not a list of objects and an
    unknown family all raise :class:`VectorError` before any case is counted,
    so nothing here can leave a partially-read fixture looking like a pass.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise VectorError(f"cannot be read ({exc.strerror or exc})") from exc
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise VectorError(f"is not valid JSON ({exc})") from exc
    if not isinstance(doc, dict):
        raise VectorError("must contain a JSON object, not a list or scalar")
    family = doc.get("family")
    if not isinstance(family, str) or not family:
        raise VectorError("is missing the required 'family' key")
    if family == CHAIN_FAMILY:
        for key in ("genesis_hash", "entries", "checkpoint"):
            if key not in doc:
                raise VectorError(f"{family} document is missing the required '{key}' key")
        if not isinstance(doc["entries"], list):
            raise VectorError(f"{family} 'entries' must be a list")
    elif family in CASE_FAMILIES:
        cases = doc.get("cases")
        if not isinstance(cases, list):
            raise VectorError(f"{family} document is missing a 'cases' list")
        for index, case in enumerate(cases):
            if not isinstance(case, dict):
                raise VectorError(f"{family} case {index} must be an object")
    else:
        raise VectorError(f"has no verifier for family {family!r}")
    return doc


def check_receipts(receipts_dir: Path, public_key: bytes | None, key_problem: str) -> int:
    """Verify the Ed25519 signature on every receipt published in the kit.

    ``public_key`` is None when no verifier key is published, and
    ``key_problem`` says why. That is not a reason to pass: a receipt that
    claims a signature nobody can check is a failure, while a v1 HMAC-only
    receipt is counted honestly as *not publicly verifiable* -- it proves
    nothing to a stranger, and saying "0 failures" about it would be a lie of
    omission.
    """
    paths = sorted(receipts_dir.glob("*.json")) if receipts_dir.is_dir() else []
    if not paths:
        print(f"no published receipts in {receipts_dir}")
        return 0
    failures = 0
    signed = unsigned = 0
    for path in paths:
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            failures += 1
            print(f"FAIL {path.name}: receipt is unreadable ({exc})")
            continue
        if not isinstance(receipt, dict) or RECEIPT_ED25519_FIELD not in receipt:
            unsigned += 1
            continue
        signed += 1
        if key_problem is not None:
            failures += 1
            print(f"FAIL {path.name}: {key_problem}")
            continue
        for problem in verify_receipt(receipt, public_key=public_key):
            failures += 1
            print(f"FAIL {path.name}: {problem}")
    print(
        f"receipts: {signed} Ed25519-verified against the published key, "
        f"{unsigned} v1 HMAC-only and not publicly verifiable, {failures} failures"
    )
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--receipts",
        default=str(RECEIPTS),
        help="directory of published receipts to check for an Ed25519 signature",
    )
    parser.add_argument(
        "--public-key",
        default=str(VERIFIER_PUBLIC_KEY),
        help="the published verifier public key document",
    )
    args = parser.parse_args(argv)

    if not VECTORS.is_dir():
        sys.exit(f"vector directory {VECTORS} does not exist")
    failures = 0
    total_checked = 0
    for path in sorted(VECTORS.glob("*.json")):
        try:
            doc = load_vector_file(path)
        except VectorError as exc:
            failures += 1
            print(f"FAIL {path.name}: {exc}")
            continue
        verifier = FAMILIES.get(path.name)
        if verifier is None:
            failures += 1
            print(f"FAIL {path.name}: no verifier registered for this file")
            continue
        if doc["family"] == CHAIN_FAMILY:
            total_checked += 1
            try:
                verifier(doc)
            except VectorError as exc:
                failures += 1
                print(f"FAIL {path.name}: {exc}")
            continue
        for case in doc["cases"]:
            total_checked += 1
            try:
                verifier(case)
            except VectorError as exc:
                failures += 1
                print(f"FAIL {path.name} [{case.get('name')}]: {exc}")
    if total_checked != EXPECTED_VECTORS:
        sys.exit(f"Expected {EXPECTED_VECTORS} vectors, got {total_checked}")
    print(f"checked {total_checked} vector cases, {failures} failures")

    public_key_path = Path(args.public_key)
    public_key = None
    key_problem = None
    if public_key_path.exists():
        try:
            public_key = load_verifier_public_key(public_key_path)
        except VectorError as exc:
            key_problem = str(exc)
    else:
        key_problem = f"no verifier key is published at {public_key_path.name}"
    receipts_rc = check_receipts(Path(args.receipts), public_key, key_problem)
    return 1 if (failures or receipts_rc) else 0


if __name__ == "__main__":
    sys.exit(main())
