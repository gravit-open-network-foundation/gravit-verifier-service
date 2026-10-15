export declare const DEFAULT_BASE: string;
export declare class ApiError extends Error { status: number; }
export interface EvidenceRecord {
  record_id: string; theta: number; result: boolean | null; verifier_id: string; timestamp: string;
  provenance: string; integrity_hash: string; key_id?: string; signature?: string;
}
export interface Artifact {
  artifact_id: string;
  claimed_state?: "Verified Fact" | "Probabilistic Assessment" | "Speculative Claim" | null;
  context?: Record<string, unknown>;
  evidence: EvidenceRecord[];
}
export interface VerifyResponse {
  result: { decision: Record<string, any>; explanation: Record<string, any> };
  receipt: Record<string, any>; signature: string; entry_hash: string;
}
export declare class Client {
  constructor(apiKey: string, baseUrl?: string);
  verify(artifact: Artifact, opts?: { registry?: { registry: string; signatures: string; trust_root: string }; useTestRegistry?: boolean }): Promise<VerifyResponse>;
  decisions(limit?: number): Promise<Array<Record<string, any>>>;
  decision(id: string): Promise<VerifyResponse>;
  export(fromSeq?: number): Promise<Record<string, any>>;
  gate(capability: string, policy: { revision: string; allowed: string[]; frontier: string[]; forbidden: string[]; override_quorum?: number },
       opts?: { action?: Record<string, unknown>; actionHash?: string; decisionId?: string; overrides?: Array<{ authority: string; action_hash: string }> }): Promise<VerifyResponse>;
  status(): Promise<{ status: string; verifier_version: string; capability_gate: string; graviteron: string }>;
  usage(): Promise<{ plan: string; plan_until: string | null; month: string; used: number; limit: number }>;
  serviceKey(): Promise<{ key_id: string; public_key: string; algorithm: string }>;
}
