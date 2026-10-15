# @gravit-open-network/verifier-client

```js
import { Client } from "@gravit-open-network/verifier-client";
const gv = new Client(process.env.GRAVIT_API_KEY);
const res = await gv.verify(artifact);
console.log(res.result.decision.final_epistemic_state, res.result.decision.status);
```

To check receipts and exports offline, use the Python client `gravit-verifier-client`
(`verify_response`, `verify_export`). Licence: Apache-2.0.
