// Nonce scope for x402 signed-request replay protection (issue #666).
//
// WHERE THE NONCE LIVES. `src/x402-guards.ts` is the pure 402-decode /
// option-selection layer and holds no nonce or session state at all (the test
// pins that). The nonce this issue is about is the `X-Vellar-Nonce` of the
// SDK → facilitator request signature in `src/x402-request-auth.ts`, whose
// verifier contract (#407, contrib/x402-wave-407-411/request-auth-vectors.ts)
// says: nonces are tracked for at least the skew window and a replayed nonce
// is rejected. What #407 left open is the SCOPE of "replayed". This module
// fixes it.
//
// THE SCOPE, AND WHY: one nonce namespace per verifying key (`keyId`), shared
// by every resource — every path, host, port and query string — for as long
// as the request could still verify. NOT per resource.
//
//   1. The signature covers only the PATH. `createSignedFetch` signs
//      `new URL(url).pathname`; host, port and query are outside the canonical
//      string (x402-request-auth.ts:273). So a captured request for
//      `https://a/verify` still verifies when replayed at `https://a/verify?x=1`,
//      `https://b/verify` or `https://a:8443/verify`. A cache keyed by the
//      resource URL sees a "different resource" each time and accepts every
//      replay — the exact miss the issue describes. Only a store that ignores
//      the resource stops it.
//   2. Two different paths legitimately signed with one nonce is a client
//      bug (one random source per client, one nonce per request), and the
//      #407 contract says a repeated nonce inside the window is a replay —
//      the verifier cannot tell the bug from an attack and must not try.
//   3. Per KEY, not global across keys: a request is bound to its key's
//      secret, so key B can never replay key A's request. Sharing one
//      namespace across tenants would let one integrator's nonce values
//      invalidate another's for no security gain.
//   4. Remembered until `timestamp + maxSkew`, the last instant the captured
//      request could still pass the skew check — tighter than "window from
//      insertion" and with no gap: after that instant the skew check rejects
//      it, so eviction is safe.
//
// The nonce is checked AFTER the signature (#407), so a forged request can
// neither probe the store nor burn a nonce a legitimate request will use.
//
// Deployment note: "session" means one verifier. A multi-process facilitator
// must back this with a shared store (the interface is three methods), or
// each worker has its own namespace and a replay to a different worker is
// accepted — the test "two independent stores" demonstrates that limitation.

import { verifyFacilitatorRequest } from "../../src/x402-request-auth";
import { REQUEST_AUTH_MAX_SKEW_SECONDS } from "../x402-wave-407-411/request-auth-vectors";

export type NonceVerdict = "fresh" | "replayed";

export interface NonceStore {
  /**
   * Record `(keyId, nonce)` for a request stamped `timestampSeconds`, observed
   * at `nowSeconds`. `"fresh"` ⇒ first sighting inside the window, now
   * consumed; `"replayed"` ⇒ already seen, no side effect.
   */
  checkAndConsume(keyId: string, nonce: string, timestampSeconds: number, nowSeconds: number): NonceVerdict;
  /** Entries currently remembered (after eviction). */
  readonly size: number;
}

/**
 * The chosen scope: per verifying key, across all resources, for the skew
 * window. In-memory; see the deployment note above.
 */
export function createSessionNonceStore(opts: { maxSkewSeconds?: number } = {}): NonceStore {
  const maxSkew = opts.maxSkewSeconds ?? REQUEST_AUTH_MAX_SKEW_SECONDS;
  /** key → (nonce → request timestamp) */
  const seen = new Map<string, Map<string, number>>();

  function evict(nowSeconds: number): void {
    for (const [key, nonces] of seen) {
      for (const [nonce, ts] of nonces) {
        // Could a request stamped `ts` still verify at `now`? If not, forget it.
        if (ts + maxSkew < nowSeconds) nonces.delete(nonce);
      }
      if (nonces.size === 0) seen.delete(key);
    }
  }

  return {
    checkAndConsume(keyId, nonce, timestampSeconds, nowSeconds) {
      evict(nowSeconds);
      let nonces = seen.get(keyId);
      if (!nonces) {
        nonces = new Map();
        seen.set(keyId, nonces);
      }
      if (nonces.has(nonce)) return "replayed";
      nonces.set(nonce, timestampSeconds);
      return "fresh";
    },
    get size() {
      let n = 0;
      for (const nonces of seen.values()) n += nonces.size;
      return n;
    },
  };
}

/**
 * THE ANTI-PATTERN, kept only as the negative control in the test: a nonce
 * cache scoped per resource identifier. Accepts the same nonce once per
 * resource, so any replay that changes the unsigned part of the URL (query,
 * host, port) or targets another path is accepted. Do not deploy.
 */
export function createPerResourceNonceCache(): {
  checkAndConsume(resource: string, nonce: string): NonceVerdict;
} {
  const seen = new Map<string, Set<string>>();
  return {
    checkAndConsume(resource, nonce) {
      let nonces = seen.get(resource);
      if (!nonces) {
        nonces = new Set();
        seen.set(resource, nonces);
      }
      if (nonces.has(nonce)) return "replayed";
      nonces.add(nonce);
      return "fresh";
    },
  };
}

export type VerifyOutcome =
  | { ok: true }
  | { ok: false; reason: "signature-or-skew" }
  | { ok: false; reason: "replayed-nonce" };

/**
 * Signature first, nonce second. `resource` is accepted and deliberately
 * IGNORED by the nonce check — it is here so a caller that has it cannot be
 * tempted to key on it, and so the test can show it makes no difference.
 */
export async function verifySignedRequest(
  secret: string,
  headers: { keyId: string; timestamp: string; nonce: string; signature: string },
  request: { method: string; path: string; body?: string; resource?: string },
  opts: { store: NonceStore; now: () => number; maxSkewSeconds?: number },
): Promise<VerifyOutcome> {
  const ok = await verifyFacilitatorRequest(
    secret,
    headers,
    { method: request.method, path: request.path, body: request.body },
    { now: opts.now, toleranceSeconds: opts.maxSkewSeconds ?? REQUEST_AUTH_MAX_SKEW_SECONDS },
  );
  if (!ok) return { ok: false, reason: "signature-or-skew" };

  const verdict = opts.store.checkAndConsume(
    headers.keyId,
    headers.nonce,
    Number(headers.timestamp),
    Math.floor(opts.now() / 1000),
  );
  return verdict === "fresh" ? { ok: true } : { ok: false, reason: "replayed-nonce" };
}
