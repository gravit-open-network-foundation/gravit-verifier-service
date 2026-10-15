// Client for the hosted Gravit Verifier API (Node 18+ and browsers: uses fetch).
// Offline verification of receipts is provided by the Python client (gravit-verifier-client),
// because the canonical JSON of decisions contains floating point numbers formatted the Python way.
export const DEFAULT_BASE = "https://gravitverifier.space/api/v1";

export class ApiError extends Error {
  constructor(status, message) { super(`${status}: ${message}`); this.status = status; }
}

export class Client {
  constructor(apiKey, baseUrl = DEFAULT_BASE) { this.apiKey = apiKey; this.base = baseUrl.replace(/\/$/, ""); }

  async call(method, path, body) {
    const r = await fetch(this.base + path, {
      method,
      headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiError(r.status, data.error || r.statusText);
    return data;
  }

  /** Decide an artifact: {artifact_id, claimed_state, context, evidence: [...]} */
  verify(artifact, { registry, useTestRegistry = true } = {}) {
    return this.call("POST", "/verify", { artifact, use_test_registry: useTestRegistry, ...(registry ? { registry } : {}) });
  }
  gate(capability, policy, { action, actionHash, decisionId, overrides } = {}) {
    return this.call("POST", "/gate", { capability, policy, ...(action ? { action } : {}), ...(actionHash ? { action_hash: actionHash } : {}),
      ...(decisionId ? { decision_id: decisionId } : {}), ...(overrides ? { overrides } : {}) });
  }
  status() { return fetch(this.base + "/status").then(r => r.json()); }
  decisions(limit = 50) { return this.call("GET", `/decisions?limit=${limit}`).then(d => d.decisions); }
  decision(id) { return this.call("GET", `/decisions/${id}`); }
  export(fromSeq = 1) { return this.call("GET", `/export?from_seq=${fromSeq}`); }
  usage() { return this.call("GET", "/usage"); }
  serviceKey() { return fetch(this.base + "/service-key").then(r => r.json()); }
}
