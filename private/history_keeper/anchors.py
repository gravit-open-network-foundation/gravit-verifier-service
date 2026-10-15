"""Time is a fact only when independent sources confirm it.

A signed tree head carries the time its writer claims. History Keeper anchors the tree head
with independent time stamping authorities (RFC 3161; optionally OpenTimestamps on Bitcoin).
Each anchor proves that the tree head existed no later than the anchor's time.

The rule follows the Gravit standard (GEVP): one source is an opinion, not a fact.
  * an anchor counts only if its token verifies against a trusted root and covers exactly
    this tree head;
  * anchors are grouped by operator (the company running the authority);
  * the time is a Verified Fact if at least `required` independent operators confirm it;
  * the established time is the `required`-th earliest of the verified times, so one
    authority that backdates cannot make the journal look older than it is.
"""

import base64
import os
import re
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# operator -> RFC 3161 endpoint. Three companies, each with its own trust chain.
DEFAULT_TSAS = {
    "DigiCert": "http://timestamp.digicert.com",
    "Sectigo": "http://timestamp.sectigo.com",
    "GlobalSign": "http://timestamp.globalsign.com/tsa/r6advanced1",
}
OPENSSL = "openssl"


@dataclass
class Anchor:
    operator: str
    kind: str  # "rfc3161" or "opentimestamps"
    token_b64: str
    time: Optional[str] = None  # verified time, YYYY-MM-DDTHH:MM:SSZ
    status: str = "unverified"  # "verified", "failed: ...", "pending"

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _run(args, data: Optional[bytes] = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=data, capture_output=True, check=False)


def request_rfc3161(digest: bytes, operator: str, url: str, timeout: int = 30) -> Anchor:
    with tempfile.TemporaryDirectory() as d:
        q = Path(d) / "q.tsq"
        r = _run([OPENSSL, "ts", "-query", "-digest", digest.hex(), "-sha256", "-cert", "-out", str(q)])
        if r.returncode:
            return Anchor(operator, "rfc3161", "", status="failed: cannot build request")
        req = urllib.request.Request(url, data=q.read_bytes(), headers={"Content-Type": "application/timestamp-query"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            token = resp.read()
    return Anchor(operator, "rfc3161", base64.b64encode(token).decode())


def default_ca_file() -> str:
    """Trusted roots: $HK_CA_FILE, or the system bundle (macOS or Debian/Ubuntu)."""
    for c in (os.environ.get("HK_CA_FILE"), "/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"):
        if c and Path(c).exists():
            return c
    raise FileNotFoundError("no CA bundle found; set HK_CA_FILE")


def verify_rfc3161(anchor: Anchor, digest: bytes, ca_file: Optional[str] = None) -> Anchor:
    """Check the token signature against trusted roots and that it covers exactly `digest`.

    The certificate chain is checked at the time written in the token (-attime), not today, so a
    token stays verifiable after the authority's certificate expires (long-term validation)."""
    ca_file = ca_file or default_ca_file()
    with tempfile.TemporaryDirectory() as d:
        tsr = Path(d) / "a.tsr"
        tsr.write_bytes(base64.b64decode(anchor.token_b64))
        text = _run([OPENSSL, "ts", "-reply", "-in", str(tsr), "-text"]).stdout.decode()
        m = re.search(r"Time stamp: (.+? GMT)", text)
        if not m:
            return Anchor(anchor.operator, anchor.kind, anchor.token_b64, None, "failed: no time in token")
        t = datetime.strptime(" ".join(m.group(1).split()).split(".")[0].replace(" GMT", ""), "%b %d %H:%M:%S %Y")
        t = t.replace(tzinfo=timezone.utc)
        v = _run([OPENSSL, "ts", "-verify", "-in", str(tsr), "-digest", digest.hex(), "-CAfile", ca_file,
                  "-attime", str(int(t.timestamp()))])
    if not (v.returncode == 0 and b"Verification: OK" in v.stdout):
        return Anchor(anchor.operator, anchor.kind, anchor.token_b64, None, "failed: token does not verify")
    return Anchor(anchor.operator, anchor.kind, anchor.token_b64, t.strftime("%Y-%m-%dT%H:%M:%SZ"), "verified")


def time_fact(anchors: List[Anchor], required: int = 2) -> Dict[str, object]:
    """Apply the independence rule to verified anchors."""
    by_op: Dict[str, str] = {}
    for a in anchors:
        if a.status == "verified" and a.time:
            by_op[a.operator] = min(by_op.get(a.operator, a.time), a.time)  # one operator = one source
    times = sorted(by_op.values())
    if len(times) < required:
        return {"state": "Probabilistic Assessment" if times else "Speculative Claim",
                "existed_no_later_than": times[-1] if times else None,
                "independent_operators": len(times), "required": required,
                "reason": f"{len(times)} independent time source(s) verified; {required} required"}
    return {"state": "Verified Fact", "existed_no_later_than": times[required - 1],
            "independent_operators": len(times), "required": required,
            "spread_seconds": int((datetime.fromisoformat(times[-1].replace("Z", "+00:00"))
                                   - datetime.fromisoformat(times[0].replace("Z", "+00:00"))).total_seconds()),
            "operators": sorted(by_op)}
