# gravit-verifier-client

Python client for the hosted [Gravit Verifier](https://gravitverifier.space) API, with **offline**
verification of signed receipts and audit exports: you do not need to trust the service to check them.

```python
from gravit_verifier_client import Client, verify_response, verify_export

gv = Client("gv_...")                     # your API key
res = gv.verify(artifact)                 # artifact: {"artifact_id", "claimed_state", "context", "evidence": [...]}
print(res["result"]["decision"]["final_epistemic_state"], res["result"]["decision"]["status"])

key = gv.service_key()                    # better: pin this key once and keep it
print(verify_response(res, key, artifact))        # signature, result hash, request hash
print(verify_export(gv.export(), key))            # every receipt signed, hash chain unbroken
```

Licence: Apache-2.0.
