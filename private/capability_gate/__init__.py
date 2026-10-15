"""Capability Gate: a fail-closed frontier state for agent capabilities.

State is a deterministic function of (capability, policy revision, evidence, overrides).
Only SAFE permits an action. Every evaluation yields a content-addressed record.
"""
import hashlib
import json

SAFE, FRONTIER, UNSAFE, UNKNOWN = "SAFE", "FRONTIER", "UNSAFE", "UNKNOWN"


class PolicyError(ValueError):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha3(obj):
    return hashlib.sha3_256(canonical(obj)).hexdigest()


def check_policy(policy):
    """Policy: {revision, allowed, frontier, forbidden, override_quorum}. The three sets must be disjoint."""
    a, f, u = (set(policy[k]) for k in ("allowed", "frontier", "forbidden"))
    if a & f or a & u or f & u:
        raise PolicyError("allowed, frontier and forbidden must be disjoint")
    if int(policy.get("override_quorum", 2)) < 2:
        raise PolicyError("override_quorum must be at least 2")
    return a, f, u


def classify(capability, policy):
    """Base state from policy alone. Not listed means UNKNOWN, never SAFE."""
    a, f, u = check_policy(policy)
    if capability in a:
        return SAFE
    if capability in u:
        return UNSAFE
    if capability in f:
        return FRONTIER
    return UNKNOWN


def evaluate(capability, action_hash, policy, decision=None, overrides=()):
    """Resolve the state for one concrete action.

    decision: a verifier decision record bound to action_hash, with
      {"action_hash", "state": "Verified Fact" | ..., "verdict": True | False | None}.
    overrides: signed approvals [{"authority": id, "action_hash"}]; distinct authorities
      at or above override_quorum lift UNSAFE to FRONTIER only, never to SAFE.
    """
    base = classify(capability, policy)
    state, reason = base, "policy"

    bound = decision if decision and decision.get("action_hash") == action_hash else None
    if decision and not bound:
        reason = "decision not bound to this action; ignored"

    if state == UNSAFE:
        auth = {o["authority"] for o in overrides if o.get("action_hash") == action_hash}
        if len(auth) >= int(policy.get("override_quorum", 2)):
            state, reason = FRONTIER, f"override by {len(auth)} distinct authorities"

    if state == FRONTIER and bound:
        v = bound.get("verdict")
        if v is False:
            state, reason = UNSAFE, "verifier verdict false"
        elif v is True and bound.get("state") == "Verified Fact":
            state, reason = SAFE, "verified fact for this action"
        else:
            reason = "no sufficient verdict; stays FRONTIER"

    record = {
        "capability": capability,
        "action_hash": action_hash,
        "policy_revision": policy["revision"],
        "base_state": base,
        "state": state,
        "permitted": state == SAFE,
        "reason": reason,
        "decision_id": bound.get("decision_id") if bound else None,
    }
    record["record_id"] = sha3(record)
    return record


class Journal:
    """Append-only, hash-chained log of evaluations."""

    def __init__(self):
        self.entries, self.head = [], "0" * 64

    def append(self, record):
        entry = {"prev": self.head, "record": record}
        self.head = sha3(entry)
        self.entries.append(entry)
        return self.head

    def verify(self):
        h = "0" * 64
        for e in self.entries:
            if e["prev"] != h:
                return False
            h = sha3(e)
        return h == self.head
