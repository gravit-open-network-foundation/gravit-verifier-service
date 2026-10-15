#!/usr/bin/env python3
"""Publish a signed, independently timestamped tree head over every receipt the service has issued.

Leaves are the entry_hash of every receipt, all accounts, in insertion order (SQLite rowid), so a
receipt once published cannot be removed or changed without changing every later tree head. Each run:
  1. computes the RFC 9162 Merkle root over all leaves;
  2. signs the tree head with the service's Ed25519 key (same key as the receipts);
  3. asks independent RFC 3161 authorities to timestamp the signed tree head;
  4. writes <web>/log/heads/<size>.json and <web>/log/latest.json.
Run daily from cron:  python3.12 ~/verifier-service/publish_log.py ~/www/gravitverifier.space/log
"""
import base64
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from history_keeper import merkle  # noqa: E402
from history_keeper.anchors import DEFAULT_TSAS, request_rfc3161, time_fact, verify_rfc3161  # noqa: E402


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def leaves(db_path):
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    rows = con.execute("SELECT entry_hash FROM entries ORDER BY rowid").fetchall()
    con.close()
    return [bytes.fromhex(r[0]) for r in rows]


def service_key():
    kp = base64.b64decode((HERE / "data" / "service.key").read_text().strip())  # libsodium keypair: seed(32) + pk(32) + pk(32)
    sk = Ed25519PrivateKey.from_private_bytes(kp[:32])
    return sk, hashlib.sha256(kp[64:96]).hexdigest()[:16]


def main(out_dir):
    out = Path(out_dir)
    (out / "heads").mkdir(parents=True, exist_ok=True)
    ls = leaves(HERE / "data" / "service.sqlite")
    if not ls:
        return print("no receipts yet")
    sk, key_id = service_key()
    head = {"format": "gravit-receipt-log-head-1", "service": "gravitverifier.space", "service_key_id": key_id,
            "tree_size": len(ls), "root": merkle.root(ls).hex(),
            "written_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    signature = base64.b64encode(sk.sign(canon(head).encode())).decode()
    digest = hashlib.sha256((canon(head) + signature).encode()).digest()
    anchors = []
    for op, url in DEFAULT_TSAS.items():
        try:
            anchors.append(verify_rfc3161(request_rfc3161(digest, op, url), digest))
        except Exception as e:  # one authority down must not stop the others
            print(f"{op}: {e}", file=sys.stderr)
    doc = {"head": head, "signature": signature, "anchored_digest": digest.hex(),
           "anchors": [a.as_dict() for a in anchors], "time": time_fact(anchors)}
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    (out / "heads" / f"{len(ls)}.json").write_text(text)
    (out / "latest.json").write_text(text)
    print(f"tree_size={len(ls)} root={head['root'][:16]} time={doc['time']['state']}")


if __name__ == "__main__":
    main(sys.argv[1])
