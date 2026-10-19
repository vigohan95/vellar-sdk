// The same nonce reused across two different resources (issue #666).
//
// Premise check first: src/x402-guards.ts is pure and holds no nonce state, so
// the nonce under test is the X-Vellar-Nonce of src/x402-request-auth.ts,
// verified under the #407 replay-window contract
// (contrib/x402-wave-407-411/request-auth-vectors.ts). Every signature below
// is produced by the real `signFacilitatorRequest` / `createSignedFetch` and
// checked by the real `verifyFacilitatorRequest`; only the clock and the nonce
// source are fixed.
//
// The scope decision and its rationale are in ./nonce-scope.ts.

import { describe, expect, it, vi } from "vitest";
import * as guards from "../../src/x402-guards";
import {
  SIGNED_REQUEST_HEADER_NAMES as H,
  createSignedFetch,
  signFacilitatorRequest,
  verifyFacilitatorRequest,
} from "../../src/x402-request-auth";
import {
  REQUEST_AUTH_MAX_SKEW_SECONDS,
  REQUEST_AUTH_VERIFIER_CONTRACT,
  verifyWithReplayWindow,
} from "../x402-wave-407-411/request-auth-vectors";
import {
  createPerResourceNonceCache,
  createSessionNonceStore,
  verifySignedRequest,
  type NonceStore,
} from "./nonce-scope";

const SECRET = "test-shared-secret";
const KEY_ID = "key-abc";
const T0 = Date.parse("2026-10-18T12:00:00.000Z");
const NONCE = "0102030405060708090a0b0c0d0e0f10";

const cfg = (over: { keyId?: string; secret?: string; nonce?: string; now?: number } = {}) => ({
  keyId: over.keyId ?? KEY_ID,
  secret: over.secret ?? SECRET,
  now: () => over.now ?? T0,
  nonce: () => over.nonce ?? NONCE,
});

type Signed = Awaited<ReturnType<typeof signFacilitatorRequest>>;
const asHeaders = (h: Signed) => ({
  keyId: h[H.keyId],
  timestamp: h[H.timestamp],
  nonce: h[H.nonce],
  signature: h[H.signature],
});

async function signed(path: string, body = "{}", over: Parameters<typeof cfg>[0] = {}) {
  const h = await signFacilitatorRequest(cfg(over), { method: "POST", path, body });
  return { headers: asHeaders(h), request: { method: "POST", path, body } };
}

const verify = (store: NonceStore, s: Awaited<ReturnType<typeof signed>>, resource?: string, now = T0) =>
  verifySignedRequest(SECRET, s.headers, { ...s.request, resource }, { store, now: () => now });

// ── premise ──────────────────────────────────────────────────────────────────

describe("premise: where nonce tracking lives (#666)", () => {
  it("src/x402-guards.ts exports no nonce or session state — it is the pure decision layer", () => {
    const names = Object.keys(guards);
    expect(names.length).toBeGreaterThan(0);
    expect(names.filter((n) => /nonce|replay|session|seen/i.test(n))).toEqual([]);
  });

  it("the #407 contract requires rejection of a replayed nonce inside the skew window, but names no scope", () => {
    expect(REQUEST_AUTH_VERIFIER_CONTRACT.replayedNonce).toBe("reject");
    expect(REQUEST_AUTH_VERIFIER_CONTRACT.nonceTrackingWindowSeconds).toBe(REQUEST_AUTH_MAX_SKEW_SECONDS);
    expect(Object.keys(REQUEST_AUTH_VERIFIER_CONTRACT).some((k) => /scope|resource/i.test(k))).toBe(false);
  });
});

// ── the issue's case: one nonce, two distinct resources ──────────────────────

describe("one nonce reused across two different resources (#666)", () => {
  it("two legitimately signed requests to /verify and /settle sharing a nonce: the second is rejected", async () => {
    const store = createSessionNonceStore();
    const a = await signed("/verify");
    const b = await signed("/settle");
    expect(a.headers.nonce).toBe(b.headers.nonce);
    expect(a.headers.signature).not.toBe(b.headers.signature); // path is signed, so these differ

    expect(await verify(store, a, "https://facilitator.example/verify")).toEqual({ ok: true });
    expect(await verify(store, b, "https://facilitator.example/settle")).toEqual({ ok: false, reason: "replayed-nonce" });
  });

  it("the naive per-resource cache accepts both — the miss the issue describes", async () => {
    const cache = createPerResourceNonceCache();
    const a = await signed("/verify");
    const b = await signed("/settle");
    expect(cache.checkAndConsume("https://facilitator.example/verify", a.headers.nonce)).toBe("fresh");
    expect(cache.checkAndConsume("https://facilitator.example/settle", b.headers.nonce)).toBe("fresh");
  });

  it("the order of resources does not matter and the first sighting is the one that wins", async () => {
    const store = createSessionNonceStore();
    const a = await signed("/verify");
    const b = await signed("/settle");
    expect(await verify(store, b)).toEqual({ ok: true });
    expect(await verify(store, a)).toEqual({ ok: false, reason: "replayed-nonce" });
    expect(await verify(store, b)).toEqual({ ok: false, reason: "replayed-nonce" });
  });
});

// ── the sharper case: a CAPTURED request replayed under another resource id ──

describe("a captured request replayed at a different resource identifier (#666)", () => {
  // Only the pathname is signed. Everything else that makes a "resource
  // identifier" distinct to a per-resource cache is free for the attacker.
  const replayTargets = [
    ["different query string", "https://facilitator.example/verify?attempt=2"],
    ["different host", "https://facilitator-2.example/verify"],
    ["different port", "https://facilitator.example:8443/verify"],
    ["different scheme", "http://facilitator.example/verify"],
    ["userinfo prefix", "https://ignored@facilitator.example/verify"],
  ] as const;

  async function capture() {
    // The SDK signs through createSignedFetch; capture what went on the wire.
    const wire = vi.fn(async (_url: string, init?: RequestInit) => new Response(null, { status: 200 }));
    const fetchImpl = createSignedFetch(cfg(), wire);
    await fetchImpl("https://facilitator.example/verify", { method: "POST", body: "{}" });
    const init = wire.mock.calls[0]![1]!;
    const h = init.headers as Record<string, string>;
    return {
      headers: { keyId: h[H.keyId]!, timestamp: h[H.timestamp]!, nonce: h[H.nonce]!, signature: h[H.signature]! },
      request: { method: "POST", path: "/verify", body: "{}" },
    };
  }

  for (const [label, target] of replayTargets) {
    it(`${label}: signature still verifies; global store rejects; per-resource cache accepts`, async () => {
      const captured = await capture();
      const store = createSessionNonceStore();
      const cache = createPerResourceNonceCache();

      // The original delivery.
      expect(await verify(store, captured, "https://facilitator.example/verify")).toEqual({ ok: true });
      expect(cache.checkAndConsume("https://facilitator.example/verify", captured.headers.nonce)).toBe("fresh");

      // The replay: same bytes, different resource identifier. The signature
      // is unchanged and valid, because the path the verifier matches on is
      // the same.
      const replayPath = new URL(target).pathname;
      expect(replayPath).toBe("/verify");
      expect(await verifyFacilitatorRequest(SECRET, captured.headers, { ...captured.request, path: replayPath }, { now: () => T0 })).toBe(true);

      expect(await verify(store, captured, target)).toEqual({ ok: false, reason: "replayed-nonce" });
      expect(cache.checkAndConsume(target, captured.headers.nonce)).toBe("fresh"); // accepted: the miss
    });
  }

  it("the classic same-resource replay is rejected too (sanity)", async () => {
    const store = createSessionNonceStore();
    const s = await signed("/verify");
    expect(await verify(store, s, "https://facilitator.example/verify")).toEqual({ ok: true });
    expect(await verify(store, s, "https://facilitator.example/verify")).toEqual({ ok: false, reason: "replayed-nonce" });
  });
});

// ── scope boundaries ─────────────────────────────────────────────────────────

describe("scope boundaries (#666)", () => {
  it("per key: the same nonce under two different keyIds is fresh for each", async () => {
    const store = createSessionNonceStore();
    const a = await signed("/verify", "{}", { keyId: "tenant-a", secret: "secret-a" });
    const b = await signed("/verify", "{}", { keyId: "tenant-b", secret: "secret-b" });
    expect(a.headers.nonce).toBe(b.headers.nonce);
    expect(await verifySignedRequest("secret-a", a.headers, a.request, { store, now: () => T0 })).toEqual({ ok: true });
    expect(await verifySignedRequest("secret-b", b.headers, b.request, { store, now: () => T0 })).toEqual({ ok: true });
    // …and key B cannot replay key A's request at all: the signature is bound to A's secret.
    expect(await verifySignedRequest("secret-b", a.headers, a.request, { store, now: () => T0 })).toEqual({ ok: false, reason: "signature-or-skew" });
  });

  it("a fresh nonce from the same key is accepted after a replayed one (the store is not poisoned)", async () => {
    const store = createSessionNonceStore();
    const a = await signed("/verify");
    await verify(store, a);
    expect(await verify(store, a)).toEqual({ ok: false, reason: "replayed-nonce" });
    const b = await signed("/verify", "{}", { nonce: "ffffffffffffffffffffffffffffffff" });
    expect(await verify(store, b)).toEqual({ ok: true });
  });

  it("two independent stores do not share state: a multi-process verifier needs a shared backing store", async () => {
    const workerA = createSessionNonceStore();
    const workerB = createSessionNonceStore();
    const s = await signed("/verify");
    expect(await verify(workerA, s)).toEqual({ ok: true });
    expect(await verify(workerB, s)).toEqual({ ok: true }); // the documented limitation
  });
});

// ── the #407 window, cross-referenced ────────────────────────────────────────

describe("replay window — cross-reference to #407 (#666)", () => {
  const ts = Math.floor(T0 / 1000);

  it("a nonce is remembered for exactly as long as its request could still verify", async () => {
    const store = createSessionNonceStore();
    const s = await signed("/verify");
    expect(await verify(store, s)).toEqual({ ok: true });

    // At the last verifiable instant the signature still passes the skew
    // check, so the store MUST still remember the nonce.
    const lastValid = (ts + REQUEST_AUTH_MAX_SKEW_SECONDS) * 1000;
    expect(await verifyFacilitatorRequest(SECRET, s.headers, s.request, { now: () => lastValid })).toBe(true);
    expect(await verify(store, s, undefined, lastValid)).toEqual({ ok: false, reason: "replayed-nonce" });
    expect(store.size).toBe(1);

    // One second later the skew check rejects it regardless, so forgetting it
    // is safe — and the store does forget it (no unbounded growth).
    const afterWindow = lastValid + 1000;
    expect(await verify(store, s, undefined, afterWindow)).toEqual({ ok: false, reason: "signature-or-skew" });
    store.checkAndConsume("other-key", "trigger-eviction", ts + REQUEST_AUTH_MAX_SKEW_SECONDS + 1, ts + REQUEST_AUTH_MAX_SKEW_SECONDS + 1);
    expect(store.size).toBe(1); // only the trigger entry remains
  });

  it("the nonce is checked AFTER the signature: a forged request neither probes nor burns a nonce", async () => {
    const store = createSessionNonceStore();
    const real = await signed("/verify");
    const forged = { ...real, headers: { ...real.headers, signature: "HMAC-SHA256 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } };

    expect(await verify(store, forged)).toEqual({ ok: false, reason: "signature-or-skew" });
    expect(store.size).toBe(0);
    expect(await verify(store, real)).toEqual({ ok: true }); // not burned by the forgery
  });

  it("the #407 helper has the right scope only if the caller shares ONE Set across resources", async () => {
    const a = await signed("/verify");
    const b = await signed("/settle");
    const now = () => T0;

    // Correct use: one Set per verifying key, regardless of resource.
    const shared = new Set<string>();
    expect(await verifyWithReplayWindow(SECRET, a.headers, a.request, { now, seenNonces: shared })).toBe(true);
    expect(await verifyWithReplayWindow(SECRET, b.headers, b.request, { now, seenNonces: shared })).toBe(false);

    // The misuse #666 warns about: a Set per resource silently accepts both.
    const perResource = new Map<string, Set<string>>();
    const setFor = (r: string) => perResource.get(r) ?? perResource.set(r, new Set()).get(r)!;
    expect(await verifyWithReplayWindow(SECRET, a.headers, a.request, { now, seenNonces: setFor("/verify") })).toBe(true);
    expect(await verifyWithReplayWindow(SECRET, b.headers, b.request, { now, seenNonces: setFor("/settle") })).toBe(true);
  });
});
