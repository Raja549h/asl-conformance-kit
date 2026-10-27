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


FAMILIES = {
    "canonical.json": verify_canonical,
    "hashing.json": verify_hashing,
    "tokens.json": verify_token,
    "audit.json": verify_audit,
    "attestation_v1.json": verify_attestation,
    "boundary_v1.json": verify_boundary_case,
}


def main() -> int:
    failures = 0
    checked = 0
    for path in sorted(VECTORS.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        family = doc["family"]
        verifier = FAMILIES.get(f"{path.name}")
        if verifier is None:
            print(f"SKIP {path.name}: no verifier for family {family!r}")
            continue
        if family in (
            "canonical-json",
            "argument-hashing",
            "token-mint-verify",
            "attestation-v1",
            "boundary-wire-v1",
        ):
            cases = doc["cases"]
            for case in cases:
                checked += 1
                try:
                    verifier(case)
                except VectorError as exc:
                    failures += 1
                    print(f"FAIL {path.name} [{case.get('name')}]: {exc}")
        elif family == "audit-chain":
            checked += 1
            try:
                verifier(doc)
            except VectorError as exc:
                failures += 1
                print(f"FAIL {path.name}: {exc}")
    print(f"checked {checked} vector cases, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
