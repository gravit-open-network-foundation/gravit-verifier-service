#!/usr/bin/env python3
"""Your first 30 minutes with the Gravit Verifier.

    pip install "git+https://github.com/gravit-open-network-foundation/gravit-verifier-service#subdirectory=sdk/python"
    python first_30_minutes.py gv_YOUR_KEY

Sends three public example artifacts to the hosted API and then checks every
answer OFFLINE: the receipt signature, the hashes and the hash chain. You do
not have to trust the service for that part.
"""
import json
import sys
import urllib.request

from gravit_verifier_client import Client, verify_export, verify_response

RAW = "https://raw.githubusercontent.com/gravit-open-network-foundation/verifier/main/examples/"
EXAMPLES = {
    "artifact_committed.json": "two operators agree, but their records are NOT signed: the claim is downgraded",
    "artifact_signed.json": "the same claim with signed records of two independent operators: Verified Fact",
    "artifact_weak_aggregation.json": "three weak votes: never a Verified Fact, however many",
}


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].startswith("gv_"):
        print(__doc__)
        return 2
    gv = Client(sys.argv[1])
    key = gv.service_key()
    print("service key", key.get("key_id"), "(pin it: compare with https://gravitverifier.space/docs/)\n")
    ok = True
    for name, what in EXAMPLES.items():
        artifact = json.load(urllib.request.urlopen(RAW + name, timeout=30))
        res = gv.verify(artifact)
        d = res["result"]["decision"]
        check = verify_response(res, key, artifact)
        ok &= check.get("ok") is True
        print(f"{name}\n  {what}\n  -> {d['final_epistemic_state']} ({d['status']})\n  offline check: {check}\n")
    exp = verify_export(gv.export(), key)
    ok &= exp.get("ok") is True
    print("your receipt chain, checked offline:", exp)
    print("\nDone. One last step: tell us one thing that was unclear or broken:")
    print("https://gravitverifier.space/contact/  or  https://github.com/gravit-open-network-foundation/verifier/issues")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
