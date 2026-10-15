# Gravit Verifier hosted service

The hosted API behind [gravitverifier.space](https://gravitverifier.space): the open-source
[Gravit Verifier](https://github.com/gravit-open-network-foundation/verifier) (pinned version) behind
API keys, with a **signed, hash-chained receipt for every decision** that anyone can check offline.

| Part | What |
|---|---|
| `public/` | PHP router, served at `/api/v1/` |
| `private/` | outside the web root: `lib.php` (keys, plans, receipts), `worker.py` (runs the verifier), `admin.php`, `data/` |
| `sdk/python` | `gravit-verifier-client`: API calls plus offline `verify_response` and `verify_export` |
| `sdk/typescript` | `@gravit/verifier-client`: API calls |
| `tests/test_api.py` | end-to-end test: decisions equal the verifier's golden vectors byte for byte, receipts and export verify, tampering is detected |

## API v1

| Endpoint | |
|---|---|
| `POST /api/v1/verify` | body `{"artifact": {...}, "use_test_registry": true, "registry": optional}` → `{result, receipt, signature, entry_hash}` |
| `GET /api/v1/decisions?limit=` | your decision history |
| `GET /api/v1/decisions/{decision_id}` | one decision with its receipt |
| `GET /api/v1/export?from_seq=` | all receipts, signed and hash-chained, for your auditor |
| `GET /api/v1/usage` | plan and monthly usage |
| `GET /api/v1/service-key` | the service's Ed25519 public key (no key needed) |
| `POST /api/v1/gate` | Capability Gate: `{capability, action or action_hash, policy, decision_id?, overrides?}` → fail-closed state `SAFE / FRONTIER / UNSAFE / UNKNOWN` with a receipt in the same chain |
| `GET /api/v1/status` | health and component versions (no key needed) |
| `GET /api/v1/log/proof/{entry_hash}` | inclusion proof of your receipt in the public receipt log, with the signed tree head; check offline with `verify_log_proof` |
| `GET /api/v1/openapi.json` | OpenAPI 3.1 description of this API (no key needed) |

Next to the decision, the result carries a **Graviteron**: how strongly the counted evidence supports the
claim (`expected`) and how much evidence stands behind it (`uncertainty`), computed with
[graviteron.evidence](https://github.com/gravit-open-network-foundation/graviteron) (vendored in
`private/graviteron_evidence`). Every operator is trusted equally for now, so its calibration is
not yet established; the decision itself is unchanged.

The request body is passed to the verifier byte for byte, so signed numbers keep their exact form.
The result in the response is the verifier's canonical JSON; `result_sha256` in the receipt covers it.

## Honest status

Early service (October 2026). Plans and prices are planned, not yet sold. The bundled registry and trust root
are **test keys** from the verifier's test suite; bring your own registry for real use.

## Public receipt log

Once a day `private/publish_log.py` builds an RFC 9162 Merkle tree over the entry hashes of **all**
receipts of all accounts, signs the tree head with the service key and has it timestamped by three
independent RFC 3161 authorities (DigiCert, Sectigo, GlobalSign; the time counts as a Verified Fact
when at least two agree). Heads are public at `https://gravitverifier.space/log/latest.json` and
`/log/heads/<size>.json`. So we cannot quietly remove or change a receipt we issued: every later head
would show it. Merkle tree and anchors are vendored from
[History Keeper](https://github.com/gravit-open-network-foundation/history-keeper).

## Capability Gate

`/v1/gate` answers one question for an AI agent: may this capability be used for this exact action?
The policy lists `allowed`, `frontier` and `forbidden` capabilities; anything else is `UNKNOWN` and blocked.
A frontier capability is permitted only with `decision_id` of a decision from `/v1/verify` in your
account that is a Verified Fact with status SUCCESS **and** whose `artifact_id` equals the action hash
(SHA3-256 of the canonical action, returned as `action_hash`). Specification and tests:
[capability-gate](https://github.com/gravit-open-network-foundation/capability-gate).

Licence: Apache-2.0.
