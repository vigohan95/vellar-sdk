// Wallet secrets never appear in a thrown WalletApiError (issue #674).
//
// Three layers, all hermetic (mocked fetch, a real signed envelope built with
// @stellar/stellar-sdk, no network):
//
//   1. CONTRACT, as it holds today: for every endpoint of the real
//      `createHttpWalletBackend` and every error-body shape `toApiError`
//      handles, no fragment of `signedXdr` / `signedTx` / `keyId` reaches the
//      error's message, String(), stack, JSON form or own properties.
//   2. THE GAP: a gateway that echoes the request into `message` or `error`
//      is repeated verbatim by the SDK. Documented here as a characterization
//      test so the day core redacts, this test flips and is removed.
//   3. THE FIX: `createRedactingHttpWalletBackend` keeps the contract even
//      against an echoing gateway, on all three endpoints, in base64, hex and
//      base64url forms, for partial echoes, and in the `code` field — and is
//      a no-op for errors that do not echo.
//
// Plus the same assertion for the error paths of src/payments-client.ts
// (whose submit path IS the WalletApiError path) and src/policy-client.ts.

import { Account, Asset, Keypair, Networks, Operation, TransactionBuilder } from "@stellar/stellar-sdk";
import { describe, expect, it, vi } from "vitest";
import { createHttpWalletBackend, WalletApiError } from "../../src/http-backend";
import { createPaymentClient, InvalidRecipientError } from "../../src/payments-client";
import { createPolicyClient } from "../../src/policy-client";
import { PolicyApiError } from "../../src/policy-types";
import type { PolicyDefinition } from "../../src/types";
import {
  FRAGMENT_WINDOW,
  RedactedWalletApiError,
  createRedactingHttpWalletBackend,
  errorSurfaces,
  findLeaks,
  findSecretFragments,
  redactSecrets,
  secretForms,
} from "./redact-request-echo";

// ── a realistic signed request body ──────────────────────────────────────────

/** A real, signed payment envelope — the thing that must never leak. */
function signedEnvelopeXdr(): string {
  const kp = Keypair.random();
  const tx = new TransactionBuilder(new Account(kp.publicKey(), "123456789"), {
    fee: "100",
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(
      Operation.payment({ destination: Keypair.random().publicKey(), asset: Asset.native(), amount: "10" }),
    )
    .setTimeout(30)
    .build();
  tx.sign(kp);
  return tx.toXDR();
}

const SIGNED_XDR = signedEnvelopeXdr();
/** A WebAuthn credential id as passkey-kit hands it over (base64url, 32 bytes). */
const KEY_ID = "pQECAyYgASFYIEt7wq7zQm9fQmX9Jk3rN1H2b8vYz6Kx0Q4lL8sT2mWn";
const API = "https://gateway.example.com";

function res(status: number, body: string, contentType = "application/json"): Response {
  return new Response(body, { status, headers: { "content-type": contentType } });
}
const json = (status: number, body: unknown) => res(status, JSON.stringify(body));

async function reject(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  throw new Error("expected rejection");
}

/** Every request shape the backend sends, with the secret-bearing fields it carries. */
const ENDPOINTS = [
  {
    name: "submitTransaction (/wallet/submit)",
    call: (b: ReturnType<typeof createHttpWalletBackend>) => b.submitTransaction({ signedXdr: SIGNED_XDR, network: "testnet" }),
    secrets: { signedXdr: SIGNED_XDR },
  },
  {
    name: "submitWalletCreation (/wallet/create) with a toXDR() signed tx",
    call: (b: ReturnType<typeof createHttpWalletBackend>) =>
      b.submitWalletCreation({ keyId: KEY_ID, contractId: "CB7PUV2W3QZ5TSEMNOGB7JOKH4VXRNFH3YNAHBXRKBRIRIEA2TVECBHZ", network: "testnet", signedTx: { toXDR: () => SIGNED_XDR } }),
    secrets: { signedTx: SIGNED_XDR, keyId: KEY_ID },
  },
  {
    name: "submitWalletCreation (/wallet/create) with a string signed tx",
    call: (b: ReturnType<typeof createHttpWalletBackend>) =>
      b.submitWalletCreation({ keyId: KEY_ID, contractId: "CB7PUV2W3QZ5TSEMNOGB7JOKH4VXRNFH3YNAHBXRKBRIRIEA2TVECBHZ", network: "testnet", signedTx: SIGNED_XDR }),
    secrets: { signedTx: SIGNED_XDR, keyId: KEY_ID },
  },
  {
    name: "lookupContractId (/wallet/connect)",
    call: (b: ReturnType<typeof createHttpWalletBackend>) => b.lookupContractId({ keyId: KEY_ID, network: "mainnet" }),
    secrets: { keyId: KEY_ID },
  },
] as const;

/** Every error-body shape `toApiError` has a branch for, plus a few it does not. */
const ERROR_BODIES = [
  ["JSON with message and error", () => json(400, { error: "INVALID_ENVELOPE", message: "Transaction envelope rejected by relayer" })],
  ["JSON with error only", () => json(422, { error: "UNSUPPORTED_NETWORK" })],
  ["JSON with neither", () => json(503, {})],
  ["JSON null", () => res(500, "null")],
  ["JSON array", () => res(500, '["boom"]')],
  ["non-JSON HTML", () => res(502, "<html><body>502 Bad Gateway</body></html>", "text/html")],
  ["empty body", () => res(500, "")],
  ["rate limited", () => json(429, { error: "RATE_LIMITED", message: "slow down" })],
] as const;

// ── 1. the contract as it holds today ────────────────────────────────────────

describe("WalletApiError built by the SDK carries no fragment of the request (#674)", () => {
  for (const ep of ENDPOINTS) {
    for (const [label, body] of ERROR_BODIES) {
      it(`${ep.name} × ${label}`, async () => {
        const fetchImpl = vi.fn<typeof fetch>(async () => body());
        const err = await reject(ep.call(createHttpWalletBackend(API, fetchImpl)));
        expect(err).toBeInstanceOf(WalletApiError);
        expect(findLeaks(err, ep.secrets)).toEqual([]);
        // The request DID carry the secret — the mock saw it on the wire.
        const sent = String(fetchImpl.mock.calls[0]![1]!.body);
        for (const secret of Object.values(ep.secrets)) expect(sent).toContain(secret);
      });
    }
  }

  it("the JSON-serialized form is exactly { status, code, name } — message is non-enumerable", async () => {
    // So a logger that JSON.stringifies errors ships only these three; the
    // only echo-controlled one among them is `code`, covered below.
    const fetchImpl = vi.fn<typeof fetch>(async () => json(409, { error: "ALREADY_EXISTS", message: "Wallet already exists" }));
    const err = (await reject(createHttpWalletBackend(API, fetchImpl).submitTransaction({ signedXdr: SIGNED_XDR, network: "testnet" }))) as WalletApiError;
    expect(JSON.parse(JSON.stringify(err))).toEqual({ status: 409, code: "ALREADY_EXISTS", name: "WalletApiError" });
    expect(Object.keys(err).sort()).toEqual(["code", "name", "status"]);
  });

  it("a transport failure (fetch throws) is not a WalletApiError and does not carry the body either", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      throw new TypeError("fetch failed");
    });
    const err = await reject(createHttpWalletBackend(API, fetchImpl).submitTransaction({ signedXdr: SIGNED_XDR, network: "testnet" }));
    expect(err).toBeInstanceOf(TypeError);
    expect(findLeaks(err, { signedXdr: SIGNED_XDR })).toEqual([]);
  });
});

// ── 2. the gap: an echoing gateway ───────────────────────────────────────────

describe("characterization: an echoing gateway's text is repeated verbatim today (#674)", () => {
  // These assert CURRENT behaviour of src/http-backend.ts. When core adopts
  // redaction (see contrib/README.md → Integration into Core) they flip; delete
  // them then, the tests in the next block are the contract.
  it("message echo → fragment reaches message, String(err) and stack", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => json(400, { error: "INVALID_ENVELOPE", message: `invalid envelope: ${SIGNED_XDR}` }));
    const err = await reject(createHttpWalletBackend(API, fetchImpl).submitTransaction({ signedXdr: SIGNED_XDR, network: "testnet" }));
    const surfaces = findLeaks(err, { signedXdr: SIGNED_XDR }).map((f) => f.surface);
    expect(surfaces).toEqual(expect.arrayContaining(["message", "toString", "stack"]));
  });

  it("error-code echo → fragment reaches code, and therefore JSON.stringify(err)", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => json(400, { error: `bad_xdr:${SIGNED_XDR.slice(0, 40)}` }));
    const err = await reject(createHttpWalletBackend(API, fetchImpl).submitTransaction({ signedXdr: SIGNED_XDR, network: "testnet" }));
    const surfaces = findLeaks(err, { signedXdr: SIGNED_XDR }).map((f) => f.surface);
    expect(surfaces).toEqual(expect.arrayContaining(["json", "ownProps"]));
  });
});

// ── 3. the fix: redaction at the boundary ────────────────────────────────────

describe("createRedactingHttpWalletBackend keeps the contract against an echoing gateway (#674)", () => {
  const echoCases = [
    ["whole envelope in message", (x: string) => ({ error: "INVALID_ENVELOPE", message: `invalid envelope: ${x}` })],
    ["first 20 chars in message", (x: string) => ({ error: "INVALID_ENVELOPE", message: `could not decode ${x.slice(0, 20)}…` })],
    ["hex form in message", (x: string) => ({ message: `raw bytes ${secretForms(x)[1]}` })],
    ["base64url form in message", (x: string) => ({ message: `got ${x.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}` })],
    ["envelope in error code", (x: string) => ({ error: `bad_xdr:${x}` })],
    ["envelope twice, message and code", (x: string) => ({ error: x, message: `${x} rejected: ${x}` })],
    ["envelope inside a longer message", (x: string) => ({ message: `relayer said: {"tx":"${x}","reason":"seq"}` })],
  ] as const;

  for (const [label, body] of echoCases) {
    it(`submitTransaction: ${label}`, async () => {
      const fetchImpl = vi.fn<typeof fetch>(async () => json(400, body(SIGNED_XDR)));
      const err = (await reject(createRedactingHttpWalletBackend(API, fetchImpl).submitTransaction({ signedXdr: SIGNED_XDR, network: "testnet" }))) as RedactedWalletApiError;
      expect(err).toBeInstanceOf(WalletApiError);
      expect(err).toBeInstanceOf(RedactedWalletApiError);
      expect(err.name).toBe("WalletApiError");
      expect(err.status).toBe(400);
      expect(findLeaks(err, { signedXdr: SIGNED_XDR })).toEqual([]);
      expect(err.redactedFields).toEqual(["signedXdr"]);
      expect(`${err.message} ${err.code ?? ""}`).toContain("[redacted:signedXdr]");
    });
  }

  it("submitWalletCreation: echoes of signedTx and keyId are both removed and both named", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => json(400, { message: `key ${KEY_ID} already bound; tx ${SIGNED_XDR}` }));
    const err = (await reject(ENDPOINTS[1].call(createRedactingHttpWalletBackend(API, fetchImpl)))) as RedactedWalletApiError;
    expect(findLeaks(err, { signedTx: SIGNED_XDR, keyId: KEY_ID })).toEqual([]);
    expect([...err.redactedFields].sort()).toEqual(["keyId", "signedTx"]);
    expect(err.message).toBe("key [redacted:keyId] already bound; tx [redacted:signedTx]");
  });

  it("lookupContractId: keyId echo removed; 404 still means 'no wallet' (undefined)", async () => {
    const echo = vi.fn<typeof fetch>(async () => json(500, { error: "LOOKUP_FAILED", message: `no row for ${KEY_ID}` }));
    const err = (await reject(createRedactingHttpWalletBackend(API, echo).lookupContractId({ keyId: KEY_ID, network: "testnet" }))) as RedactedWalletApiError;
    expect(findLeaks(err, { keyId: KEY_ID })).toEqual([]);
    expect(err.redactedFields).toEqual(["keyId"]);

    const notFound = vi.fn<typeof fetch>(async () => json(404, { error: "NOT_FOUND", message: `no row for ${KEY_ID}` }));
    await expect(createRedactingHttpWalletBackend(API, notFound).lookupContractId({ keyId: KEY_ID, network: "testnet" })).resolves.toBeUndefined();
  });

  it("is a no-op for an error that does not echo: same message, same code, nothing redacted", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => json(422, { error: "UNSUPPORTED_NETWORK", message: "futurenet is not supported" }));
    const err = (await reject(createRedactingHttpWalletBackend(API, fetchImpl).submitTransaction({ signedXdr: SIGNED_XDR, network: "testnet" }))) as RedactedWalletApiError;
    expect(err.message).toBe("futurenet is not supported");
    expect(err.code).toBe("UNSUPPORTED_NETWORK");
    expect(err.status).toBe(422);
    expect(err.redactedFields).toEqual([]);
  });

  it("leaves success responses and non-WalletApiError failures untouched", async () => {
    const ok = vi.fn<typeof fetch>(async () => json(200, { hash: "abc" }));
    await expect(createRedactingHttpWalletBackend(API, ok).submitTransaction({ signedXdr: SIGNED_XDR, network: "testnet" })).resolves.toEqual({ hash: "abc" });

    const transport = vi.fn<typeof fetch>(async () => {
      throw new TypeError("fetch failed");
    });
    await expect(createRedactingHttpWalletBackend(API, transport).submitTransaction({ signedXdr: SIGNED_XDR, network: "testnet" })).rejects.toThrow(TypeError);

    await expect(
      createRedactingHttpWalletBackend(API, ok).submitWalletCreation({ keyId: KEY_ID, contractId: "C1", network: "testnet", signedTx: 42 }),
    ).rejects.toThrow("Cannot convert signed transaction to XDR");
  });

  it("sends byte-identical requests to the plain backend", async () => {
    const a = vi.fn<typeof fetch>(async () => json(200, { hash: "x" }));
    const b = vi.fn<typeof fetch>(async () => json(200, { hash: "x" }));
    for (const ep of ENDPOINTS) {
      a.mockClear();
      b.mockClear();
      await ep.call(createHttpWalletBackend(API, a));
      await ep.call(createRedactingHttpWalletBackend(API, b));
      expect(b.mock.calls).toEqual(a.mock.calls);
    }
  });
});

// ── guards the guard ─────────────────────────────────────────────────────────

describe("the leak detector itself (#674)", () => {
  it("catches a planted window-sized fragment and ignores one character less", () => {
    // From the signature at the tail of the envelope: high entropy, so the
    // one-shorter negative case cannot match some other window by accident.
    const fragment = SIGNED_XDR.slice(-60, -60 + FRAGMENT_WINDOW);
    expect(findSecretFragments(`error near ${fragment} here`, SIGNED_XDR)).toEqual([fragment]);
    expect(findSecretFragments(`error near ${fragment.slice(1)} here`, SIGNED_XDR)).toEqual([]);
    expect(findSecretFragments("", SIGNED_XDR)).toEqual([]);
  });

  it("knows the hex and base64url forms of a base64 envelope", () => {
    const forms = secretForms(SIGNED_XDR);
    expect(forms[0]).toBe(SIGNED_XDR);
    expect(forms[1]).toMatch(/^[0-9a-f]+$/);
    expect(forms.some((f) => !f.includes("+") && !f.includes("/") && !f.endsWith("="))).toBe(true);
  });

  it("inspects message, String(), stack, JSON and own props", () => {
    const e = new WalletApiError("msg", 500, "CODE");
    expect(Object.keys(errorSurfaces(e))).toEqual(["message", "toString", "stack", "json", "ownProps", "cause"]);
  });

  it("redactSecrets collapses the longest run and reports the field once", () => {
    const { text, fields } = redactSecrets(`a ${SIGNED_XDR} b ${SIGNED_XDR.slice(0, 30)} c`, { signedXdr: SIGNED_XDR });
    expect(text).toBe("a [redacted:signedXdr] b [redacted:signedXdr] c");
    expect(fields).toEqual(["signedXdr"]);
  });
});

// ── payments-client: its submit path is the WalletApiError path ──────────────

describe("payments-client error paths carry no signed material (#674)", () => {
  const to = "GAVU25UK4ISUJIH6KWLXX6XDKKCR3GNZ27RZ5WABRSE42ZADV2LB3ZLU";
  const from = "CAFIATCEAZJTGQQKFL3N2YB6VMCUN2UYX4QD5A3FALDRU7UJJ6OWBKOW";
  const token = { contractId: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA", code: "XLM", symbol: "XLM", decimals: 7 };

  function client(fetchImpl: typeof fetch, redacting = false) {
    const sign = vi.fn(async () => ({ toXDR: () => SIGNED_XDR }));
    const backend = redacting ? createRedactingHttpWalletBackend(API, fetchImpl) : createHttpWalletBackend(API, fetchImpl);
    const c = createPaymentClient({
      kit: { sign },
      sac: { getSACClient: () => ({ transfer: async () => ({ built: true }) }) },
      backend,
      network: "testnet",
      isValidAddress: (a) => a.startsWith("G") || a.startsWith("C"),
    });
    return { c, sign };
  }

  it("validation errors are thrown before anything is signed, so there is nothing to leak", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const { c, sign } = client(fetchImpl);
    const err = await reject(c.preparePayment({ from, to: "not-an-address", token, amount: 1n }));
    expect(err).toBeInstanceOf(InvalidRecipientError);
    expect((err as Error).message).toContain("not-an-address"); // the recipient is public input, by design
    expect(sign).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("confirm() → gateway rejects with a non-echoing error: no fragment of the signed XDR anywhere", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => json(400, { error: "SEQ_MISMATCH", message: "bad sequence" }));
    const { c } = client(fetchImpl);
    const prepared = await c.preparePayment({ from, to, token, amount: 10n });
    const err = await reject(prepared.confirm());
    expect(err).toBeInstanceOf(WalletApiError);
    expect(findLeaks(err, { signedXdr: SIGNED_XDR })).toEqual([]);
  });

  it("confirm() → echoing gateway: leaks through the plain backend, contained by the redacting one", async () => {
    const echo = () => vi.fn<typeof fetch>(async () => json(400, { message: `relayer rejected ${SIGNED_XDR}` }));

    const plain = client(echo());
    const leaked = await reject((await plain.c.preparePayment({ from, to, token, amount: 10n })).confirm());
    expect(findLeaks(leaked, { signedXdr: SIGNED_XDR }).length).toBeGreaterThan(0); // characterization

    const guarded = client(echo(), true);
    const contained = await reject((await guarded.c.preparePayment({ from, to, token, amount: 10n })).confirm());
    expect(contained).toBeInstanceOf(WalletApiError);
    expect(findLeaks(contained, { signedXdr: SIGNED_XDR })).toEqual([]);
  });
});

// ── policy-client: no secret-bearing request fields, and the error still ─────
// ── never carries the request ────────────────────────────────────────────────

describe("policy-client error paths (#674)", () => {
  const definition: PolicyDefinition = {
    version: "1",
    type: "spending_limit",
    owners: ["CAFK7NMQOT7G2SKMREDUII3EOK4APIY54WIK6CVGY72XWFE76YFRDF67"],
    spendingLimits: { dailyXlm: "100" },
  };
  const wallet = "CB7PUV2W3QZ5TSEMNOGB7JOKH4VXRNFH3YNAHBXRKBRIRIEA2TVECBHZ";
  const txHash = "9d3f1a2b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7";

  it("every policy request field is public chain data — none is secret-bearing", async () => {
    // Pinning the request surface: if a secret-bearing field is ever added to
    // a policy request, this test is where the no-secrets contract must extend.
    const fetchImpl = vi.fn<typeof fetch>(async () => json(500, {}));
    const client = createPolicyClient({ apiUrl: API, network: "testnet", fetch: fetchImpl });
    await reject(client.generate(definition));
    await reject(client.simulate("p1", wallet));
    await reject(client.recordDeployment("p1", txHash, wallet));
    const sentKeys = fetchImpl.mock.calls.flatMap((c) => Object.keys(JSON.parse(String(c[1]!.body)) as object)).sort();
    expect(sentKeys).toEqual(["contractId", "definition", "network", "policyId", "txHash", "wallet"]);
    for (const k of sentKeys) expect(k).not.toMatch(/xdr|signed|secret|token|session|key/i);
  });

  it("PolicyApiError built from a non-echoing gateway never carries the request body", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => json(422, { error: "invalid_definition", errors: ["owners[0] is not a valid address"] }));
    const client = createPolicyClient({ apiUrl: API, network: "testnet", fetch: fetchImpl });
    const err = (await reject(client.generate(definition))) as PolicyApiError;
    expect(err).toBeInstanceOf(PolicyApiError);
    const everything = Object.values(errorSurfaces(err)).join("\n");
    expect(everything).not.toContain(JSON.stringify(definition));
    expect(everything).not.toContain(definition.owners[0]!);
    expect(JSON.parse(JSON.stringify(err))).toEqual({
      name: "PolicyApiError",
      status: 422,
      errors: ["owners[0] is not a valid address"],
      retryable: false,
    });
  });

  it("a transport failure surfaces only fetch's own message", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      throw new TypeError("fetch failed");
    });
    const client = createPolicyClient({ apiUrl: API, network: "testnet", fetch: fetchImpl });
    const err = (await reject(client.simulate("p1", wallet))) as PolicyApiError;
    expect(err.status).toBe(0);
    expect(Object.values(errorSurfaces(err)).join("\n")).not.toContain(wallet);
  });
});
