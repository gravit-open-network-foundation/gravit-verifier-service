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

The request body is passed to the verifier byte for byte, so signed numbers keep their exact form.
The result in the response is the verifier's canonical JSON; `result_sha256` in the receipt covers it.

## Honest status

Early service (October 2026). Plans and prices are planned, not yet sold. The bundled registry and trust root
are **test keys** from the verifier's test suite; bring your own registry for real use.

Licence: Apache-2.0.
