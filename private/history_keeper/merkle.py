"""Merkle tree of the journal, hashed as in RFC 9162 (Certificate Transparency v2).

leaf hash  = SHA-256(0x00 || entry bytes)
node hash  = SHA-256(0x01 || left || right)
The tree over n leaves splits at the largest power of two smaller than n. This is the
construction SCITT receipts use for inclusion proofs, so a History Keeper journal can be
checked with the same mathematics as a transparency log.
"""

import hashlib
from typing import List, Sequence


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(leaves: Sequence[bytes]) -> bytes:
    """Merkle tree hash of the given leaf hashes (RFC 9162, section 2.1.1). Empty tree: SHA-256 of ''."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def inclusion_proof(leaves: Sequence[bytes], index: int) -> List[bytes]:
    """Audit path for leaf `index` in the tree over `leaves` (RFC 9162, section 2.1.3)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [root(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], expected_root: bytes) -> bool:
    """Check an audit path (RFC 9162, section 2.1.3.2)."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root
