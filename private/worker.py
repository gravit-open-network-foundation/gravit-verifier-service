#!/usr/bin/env python3
"""Decide one artifact with the Gravit Verifier; called by the PHP API.

stdin:  the raw API request body, unchanged:
        {"artifact": {...}, "registry": optional {"registry": "<json text>", "signatures": "<text>", "trust_root": "<json text>"},
         "use_test_registry": optional bool, default true}
stdout: line 1: {"ok": true, "request_sha256", "decision_id", "artifact_id", "state", "status", "verifier_version"}
        line 2: the result {"decision": ..., "explanation": ...} as canonical JSON (sorted keys, no whitespace)
        or one line {"ok": false, "error": "..."}. Exit code 0 in both cases; non-zero only on a crash.
"""
import hashlib
import json
import sys
from pathlib import Path

import gravit_verifier
from gravit_verifier.explain import explain
from gravit_verifier.kernel import EpistemicState, EvidenceRecord, VerificationRequest, VerifierKernel
from gravit_verifier.registry import RegistryError, TrustRoot, VerifierRegistry

DATA = Path(__file__).resolve().parent / "data"
FIELDS = ("record_id", "theta", "result", "verifier_id", "timestamp", "provenance", "integrity_hash")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fail(msg):
    print(json.dumps({"ok": False, "error": msg}))
    sys.exit(0)


def request_from(a):
    if not isinstance(a, dict) or not isinstance(a.get("artifact_id"), str) or not a["artifact_id"]:
        fail("artifact.artifact_id must be a non-empty string")
    evidence = a.get("evidence", [])
    if not isinstance(evidence, list) or len(evidence) > 500:
        fail("artifact.evidence must be a list of at most 500 records")
    records = []
    for i, e in enumerate(evidence):
        if not isinstance(e, dict):
            fail(f"evidence[{i}] must be an object")
        missing = [k for k in FIELDS if k not in e]
        if missing:
            fail(f"evidence[{i}] lacks {', '.join(missing)}")
        records.append(EvidenceRecord(**{k: e[k] for k in FIELDS},
                                      key_id=e.get("key_id", ""), signature=e.get("signature", "")))
    claimed = a.get("claimed_state")
    try:
        state = EpistemicState(claimed) if claimed else None
    except ValueError:
        fail("claimed_state must be one of: " + ", ".join(s.value for s in EpistemicState))
    context = a.get("context", {})
    if not isinstance(context, dict):
        fail("artifact.context must be an object")
    return VerificationRequest(a["artifact_id"], state, records, context)


def main():
    try:
        job = json.load(sys.stdin)
    except ValueError:
        fail("request body is not valid JSON")
    registry = None
    try:
        if job.get("registry"):
            r = job["registry"]
            registry = VerifierRegistry.from_bytes(r["registry"].encode(), r["signatures"],
                                                   TrustRoot.from_bytes(r["trust_root"].encode()))
        elif job.get("use_test_registry", True):
            registry = VerifierRegistry.from_file(DATA / "test-registry.json",
                                                  TrustRoot.from_file(DATA / "test-trust-root.json"))
    except (RegistryError, KeyError, TypeError, ValueError) as e:
        fail(f"registry not accepted: {e}")
    kernel = VerifierKernel(registry)
    for b in json.loads((DATA / "bindings.json").read_text()):
        kernel.load_binding(b)
    req = request_from(job.get("artifact"))
    try:
        d = kernel.verify(req)
    except Exception as e:  # malformed field types inside records
        fail(f"artifact could not be evaluated: {type(e).__name__}: {e}")
    result = canon({"decision": d.to_dict(), "explanation": explain(req, d, kernel)})
    meta = {"ok": True, "request_sha256": hashlib.sha256(canon(job.get("artifact")).encode()).hexdigest(),
            "decision_id": d.decision_id, "artifact_id": d.artifact_id, "status": d.status.value,
            "state": d.final_epistemic_state.value if d.final_epistemic_state else None,
            "verifier_version": gravit_verifier.__version__}
    sys.stdout.write(canon(meta) + "\n" + result + "\n")

if __name__ == "__main__":
    main()
