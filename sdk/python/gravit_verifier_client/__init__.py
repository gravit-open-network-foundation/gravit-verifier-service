"""Client for the hosted Gravit Verifier API.

    from gravit_verifier_client import Client, verify_response, verify_export
    gv = Client("gv_...")
    res = gv.verify({"artifact_id": "...", "claimed_state": "Verified Fact", "evidence": [...]})
    res["result"]["decision"]["final_epistemic_state"]
    verify_response(res, gv.service_key())      # offline: signature and hashes, no trust in the service needed

Only the standard library is used for HTTP; `cryptography` is needed for the offline checks.
"""
import base64
import hashlib
import json
import urllib.error
import urllib.request

__all__ = ["Client", "ApiError", "canonical", "verify_response", "verify_export"]
__version__ = "0.1.0"
DEFAULT_BASE = "https://gravitverifier.space/api/v1"


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(f"{status}: {message}")
        self.status, self.message = status, message


def canonical(obj):
    """The canonical JSON the service hashes and signs: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class Client:
    def __init__(self, api_key, base_url=DEFAULT_BASE, timeout=30):
        self.api_key, self.base, self.timeout = api_key, base_url.rstrip("/"), timeout

    def _call(self, method, path, body=None):
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {self.api_key}",
                                              "Content-Type": "application/json",
                                              "User-Agent": f"gravit-verifier-client/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode()).get("error", e.reason)
            except ValueError:
                msg = e.reason
            raise ApiError(e.code, msg) from None

    def verify(self, artifact, registry=None, use_test_registry=True):
        """Decide an artifact. `registry` = {"registry": json_text, "signatures": text, "trust_root": json_text}."""
        body = {"artifact": artifact, "use_test_registry": use_test_registry}
        if registry:
            body["registry"] = registry
        return self._call("POST", "/verify", body)

    def gate(self, capability, policy, action=None, action_hash=None, decision_id=None, overrides=None):
        """Capability Gate: may `capability` be used for this exact action? Fail-closed; only state SAFE permits.
        A frontier capability needs decision_id of a Verified Fact whose artifact_id equals the action hash."""
        body = {"capability": capability, "policy": policy}
        if action is not None:
            body["action"] = action
        if action_hash is not None:
            body["action_hash"] = action_hash
        if decision_id is not None:
            body["decision_id"] = decision_id
        if overrides:
            body["overrides"] = overrides
        return self._call("POST", "/gate", body)

    def status(self):
        req = urllib.request.Request(self.base + "/status")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def decisions(self, limit=50, before_seq=None):
        q = f"?limit={int(limit)}" + (f"&before_seq={int(before_seq)}" if before_seq else "")
        return self._call("GET", "/decisions" + q)["decisions"]

    def decision(self, decision_id):
        return self._call("GET", f"/decisions/{decision_id}")

    def export(self, from_seq=1):
        return self._call("GET", f"/export?from_seq={int(from_seq)}")

    def usage(self):
        return self._call("GET", "/usage")

    def service_key(self):
        req = urllib.request.Request(self.base + "/service-key")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())


def _check_signature(receipt, signature_b64, key_doc):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if receipt.get("service_key_id") != key_doc["key_id"]:
        return "receipt was signed by a different service key"
    pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(key_doc["public_key"]))
    try:
        pk.verify(base64.b64decode(signature_b64), canonical(receipt).encode())
    except InvalidSignature:
        return "signature does not verify"
    return None


def verify_response(response, key_doc, artifact=None):
    """Offline check of one /verify or /decisions/{id} response. Returns {"ok": bool, "problems": [...]}."""
    problems = []
    rc = response["receipt"]
    p = _check_signature(rc, response["signature"], key_doc)
    if p:
        problems.append(p)
    if hashlib.sha256(canonical(response["result"]).encode()).hexdigest() != rc["result_sha256"]:
        problems.append("result does not match result_sha256 in the receipt")
    if response.get("entry_hash") and hashlib.sha256(canonical(rc).encode()).hexdigest() != response["entry_hash"]:
        problems.append("entry_hash does not match the receipt")
    if rc["decision_id"] != response["result"]["decision"]["decision_id"]:
        problems.append("decision_id differs between receipt and result")
    if artifact is not None and hashlib.sha256(canonical(artifact).encode()).hexdigest() != rc["request_sha256"]:
        problems.append("the artifact you sent does not match request_sha256")
    return {"ok": not problems, "problems": problems}


def verify_export(export, key_doc=None):
    """Offline check of an /export: every signature, and an unbroken hash chain from the first entry.
    Pass key_doc obtained independently (e.g. pinned) instead of trusting the key inside the export."""
    key_doc = key_doc or export["service_key"]
    problems, prev = [], None
    for i, e in enumerate(export["entries"]):
        rc = e["receipt"]
        p = _check_signature(rc, e["signature"], key_doc)
        if p:
            problems.append(f"entry {i} (seq {rc.get('seq')}): {p}")
        if rc.get("account") != export["account"]:
            problems.append(f"entry {i}: belongs to another account")
        if prev is not None:
            if rc["prev_entry_hash"] != prev[1] or rc["seq"] != prev[0] + 1:
                problems.append(f"entry {i} (seq {rc['seq']}): chain broken")
        elif rc["seq"] == 1 and rc["prev_entry_hash"] != "0" * 64:
            problems.append("first entry does not start the chain")
        prev = (rc["seq"], hashlib.sha256(canonical(rc).encode()).hexdigest())
    return {"ok": not problems, "entries": len(export["entries"]), "head": prev[1] if prev else None, "problems": problems}
