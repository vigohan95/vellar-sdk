// Fuzz test for the policy-service response parser (issue #675).
//
// Two targets, same generated inputs:
//   1. the REAL `createPolicyClient` from src/policy-client.ts — to find out what
//      a hostile gateway body does to it today, and to pin every crash as a
//      named regression test;
//   2. `createParsedPolicyClient` from ./policy-response-parser.ts — the
//      reference fix, which must satisfy the issue's invariant: never an
//      unhandled exception, always either a value of the declared type or a
//      named error (`PolicyApiError` | `PolicyParseError`).
//
// The generator is a seeded PRNG over structured mutations of VALID response
// fixtures (so most payloads are "almost right" — the class that slips past a
// cast) plus text-level corruption (so invalid JSON, `null`, empty bodies and
// duplicate keys are covered too). Seeds are fixed; a failure message carries
// the seed and iteration so the exact payload can be regenerated. No external
// dependency — same choice as contrib/x402-untrusted-property.test.ts.

import { describe, expect, it, vi } from "vitest";
import { createPolicyClient, type PolicyClient } from "../../src/policy-client";
import { PolicyApiError, type GeneratedPolicy, type PolicyTemplateInfo } from "../../src/policy-types";
import type { PolicyDefinition } from "../../src/types";
import {
  VALID_NO_ENFORCEMENT_TEMPLATE,
  VALID_SIGNER_LIMITS_TEMPLATE,
  VALID_SPENDING_LIMIT_TEMPLATE,
} from "../policy-template-validation";
import {
  MAX_RESPONSE_DEPTH,
  PolicyParseError,
  createParsedPolicyClient,
  isNamedPolicyError,
  parseDeployInstanceResult,
  parseGeneratedPolicy,
  parsePolicyEnvelope,
  parsePolicyTemplateList,
  parseSimulateResult,
  parseValidationResult,
  readBody,
} from "./policy-response-parser";

// ── fixtures: what a well-behaved gateway sends ──────────────────────────────

const DEFINITION: PolicyDefinition = {
  version: "1",
  type: "spending_limit",
  owners: ["CAFK7NMQOT7G2SKMREDUII3EOK4APIY54WIK6CVGY72XWFE76YFRDF67"],
  threshold: 1,
  spendingLimits: { dailyXlm: "100", perTxXlm: "10" },
};

const POLICY: GeneratedPolicy = {
  id: "pol_01HZX6K9S7Q4M2N8R3T5V7W9Y1",
  createdAt: "2026-10-01T12:00:00.000Z",
  status: "instance_deployed",
  definition: DEFINITION,
  policyHash: "5f8c2a1d9e7b4c6a3f1e0d2c4b6a8e9f7d5c3b1a0f2e4d6c8b0a1f3e5d7c9b2a",
  manifest: {
    template: "spending_limit",
    enforcement: {
      kind: "policy-contract",
      wasmHash: "a3b1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      constructorArgs: { dailyLimitStroops: "1000000000", windowSeconds: 86400 },
    },
    network: "testnet",
  },
  instance: {
    contractId: "CB7PUV2W3QZ5TSEMNOGB7JOKH4VXRNFH3YNAHBXRKBRIRIEA2TVECBHZ",
    txHash: "9d3f1a2b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7",
    deployedAt: "2026-10-01T12:00:05.000Z",
  },
};

const TEMPLATES: PolicyTemplateInfo[] = [
  VALID_SPENDING_LIMIT_TEMPLATE,
  VALID_SIGNER_LIMITS_TEMPLATE,
  VALID_NO_ENFORCEMENT_TEMPLATE,
];

type Endpoint = {
  name: string;
  /** The well-formed 2xx body for this endpoint. */
  fixture: unknown;
  call: (c: PolicyClient) => Promise<unknown>;
  /** Re-parse a resolved value: the parsed client's output must round-trip. */
  reparse: (v: unknown) => unknown;
};

const ENDPOINTS: Endpoint[] = [
  {
    name: "listTemplates",
    fixture: TEMPLATES,
    call: (c) => c.listTemplates(),
    reparse: (v) => parsePolicyTemplateList(v),
  },
  {
    name: "listPolicies",
    fixture: [POLICY, { ...POLICY, id: "pol_2", status: "generated", instance: undefined }],
    call: (c) => c.listPolicies({ status: "active" }),
    reparse: (v) => (v as unknown[]).map((p) => parseGeneratedPolicy(p)),
  },
  {
    name: "validate",
    fixture: { valid: false, errors: ["owners[0] is not a valid address"] },
    call: (c) => c.validate(DEFINITION),
    reparse: (v) => parseValidationResult(v),
  },
  {
    name: "generate",
    fixture: { policy: { ...POLICY, status: "generated", instance: undefined } },
    call: (c) => c.generate(DEFINITION),
    reparse: (v) => parseGeneratedPolicy(v),
  },
  {
    name: "simulate",
    fixture: { ok: true, minResourceFee: "123456" },
    call: (c) => c.simulate(POLICY.id, POLICY.definition.owners[0]!),
    reparse: (v) => parseSimulateResult(v),
  },
  {
    name: "deployInstance",
    fixture: { contractId: POLICY.instance!.contractId },
    call: (c) => c.deployInstance(POLICY.id, POLICY.definition.owners[0]!),
    reparse: (v) => parseDeployInstanceResult(v),
  },
  {
    name: "recordDeployment",
    fixture: {
      policy: {
        ...POLICY,
        status: "deployed",
        deployment: { txHash: POLICY.instance!.txHash, deployedAt: POLICY.instance!.deployedAt },
      },
    },
    call: (c) => c.recordDeployment(POLICY.id, POLICY.instance!.txHash, POLICY.instance!.contractId),
    reparse: (v) => parseGeneratedPolicy(v),
  },
];

// ── seeded PRNG + generators ─────────────────────────────────────────────────

/** mulberry32 — small, deterministic, good enough to pick mutations. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type Rnd = () => number;
const pick = <T>(rnd: Rnd, arr: readonly T[]): T => arr[Math.floor(rnd() * arr.length)]!;
const int = (rnd: Rnd, max: number): number => Math.floor(rnd() * max);

const HOSTILE_STRINGS = [
  "",
  " ",
  "null",
  "undefined",
  "NaN",
  "-1",
  "1e309",
  "0x1f",
  "__proto__",
  "constructor",
  "deployed2",
  "futurenet",
  "policy-contract ",
  "\u0000",
  "‮evil",
  "﻿bom",
  "💥".repeat(3),
  "\ud800", // lone surrogate
  "<script>alert(1)</script>",
  "'; DROP TABLE policies; --",
  "x".repeat(65_536),
];

function randomJsonValue(rnd: Rnd, depth = 0): unknown {
  const r = rnd();
  if (depth > 3 || r < 0.5) {
    const leaf = int(rnd, 7);
    switch (leaf) {
      case 0:
        return null;
      case 1:
        return rnd() < 0.5;
      case 2:
        return pick(rnd, [0, -0, 1, -1, 2 ** 53, -(2 ** 53), 1e300, 1e-300, 0.1, 86400, 4294967296]);
      case 3:
        return pick(rnd, HOSTILE_STRINGS);
      case 4:
        return String(int(rnd, 1_000_000));
      case 5:
        return [];
      default:
        return {};
    }
  }
  if (r < 0.75) return Array.from({ length: int(rnd, 4) }, () => randomJsonValue(rnd, depth + 1));
  const o: Record<string, unknown> = {};
  for (let i = 0; i < int(rnd, 4); i++) o[pick(rnd, ["kind", "id", "status", "policy", "x", "__proto__"])] = randomJsonValue(rnd, depth + 1);
  return o;
}

/** Every path (as a key list) in a JSON value, root excluded. */
function collectPaths(value: unknown): Array<Array<string | number>> {
  const out: Array<Array<string | number>> = [];
  const stack: Array<{ v: unknown; p: Array<string | number> }> = [{ v: value, p: [] }];
  while (stack.length) {
    const { v, p } = stack.pop()!;
    if (p.length) out.push(p);
    if (Array.isArray(v)) v.forEach((item, i) => stack.push({ v: item, p: [...p, i] }));
    else if (typeof v === "object" && v !== null) {
      for (const k of Object.keys(v)) stack.push({ v: (v as Record<string, unknown>)[k], p: [...p, k] });
    }
  }
  return out;
}

function getAt(root: unknown, path: Array<string | number>): unknown {
  let cur: unknown = root;
  for (const k of path) {
    if (typeof cur !== "object" || cur === null) return undefined;
    cur = (cur as Record<string | number, unknown>)[k];
  }
  return cur;
}

/** Set (or delete) at `path`; returns the root, which is replaced when path is empty. */
function setAt(root: unknown, path: Array<string | number>, value: unknown, del = false): unknown {
  if (path.length === 0) return del ? undefined : value;
  const parent = getAt(root, path.slice(0, -1));
  if (typeof parent !== "object" || parent === null) return root;
  const key = path[path.length - 1]!;
  if (del) delete (parent as Record<string | number, unknown>)[key];
  else (parent as Record<string | number, unknown>)[key] = value;
  return root;
}

/** Structured mutations over a deep-cloned fixture. Returns a JSON value. */
function mutateValue(rnd: Rnd, value: unknown): unknown {
  const root = JSON.parse(JSON.stringify(value)) as unknown;
  const paths = collectPaths(root);
  const steps = 1 + int(rnd, 3);
  let current = root;
  for (let s = 0; s < steps; s++) {
    const op = int(rnd, 10);
    const target = paths.length ? pick(rnd, paths) : [];
    switch (op) {
      case 0: // replace the whole body with a wrong top-level type
        current = pick(rnd, [null, true, 0, "", "[]", "{}", [], {}, [current], { data: current }]);
        break;
      case 1: // drop a key
        current = setAt(current, target, undefined, true);
        break;
      case 2: // swap a leaf/subtree for a random JSON value
        current = setAt(current, target, randomJsonValue(rnd));
        break;
      case 3: // null it
        current = setAt(current, target, null);
        break;
      case 4: // stringify a non-string, or number-ify a string
        {
          const v = getAt(current, target);
          current = setAt(current, target, typeof v === "string" ? Number(v) || 7 : JSON.stringify(v));
        }
        break;
      case 5: // enum / shape poison on known fields
        current = setAt(current, target, pick(rnd, HOSTILE_STRINGS));
        break;
      case 6: // nesting bomb at a leaf
        {
          let bomb: unknown = pick(rnd, HOSTILE_STRINGS);
          const depth = pick(rnd, [MAX_RESPONSE_DEPTH + 1, 64, 512, 4096]);
          for (let i = 0; i < depth; i++) bomb = rnd() < 0.5 ? [bomb] : { a: bomb };
          current = setAt(current, target, bomb);
        }
        break;
      case 7: // prototype-pollution shaped keys
        if (typeof current === "object" && current !== null && !Array.isArray(current)) {
          (current as Record<string, unknown>)[pick(rnd, ["__proto__", "constructor", "prototype"])] = {
            polluted: true,
          };
        } else {
          current = setAt(current, target, { __proto__: { polluted: true }, constructor: { prototype: { polluted: true } } });
        }
        break;
      case 8: // wrap a subtree in an array (object expected) or unwrap an array
        {
          const v = getAt(current, target);
          current = setAt(current, target, Array.isArray(v) ? v[0] : [v]);
        }
        break;
      default: // extra keys everywhere
        if (typeof current === "object" && current !== null && !Array.isArray(current)) {
          for (let i = 0; i < 3; i++) (current as Record<string, unknown>)[`extra${i}`] = randomJsonValue(rnd);
        }
    }
  }
  return current;
}

/** Text-level corruption: things that are not (or not exactly) JSON. */
function corruptText(rnd: Rnd, json: string): string {
  switch (int(rnd, 10)) {
    case 0:
      return json.slice(0, int(rnd, json.length));
    case 1:
      return json + pick(rnd, ["}", "]", ",", "null", "garbage", "\u0000"]);
    case 2:
      return "﻿" + json;
    case 3:
      return json.replace(/"/g, "'");
    case 4:
      return json.replace(/:\s*"[^"]*"/, ": NaN");
    case 5:
      return json.replace(/^\{/, '{"id":"dup","id":42,');
    case 6:
      return "";
    case 7:
      return "null";
    case 8:
      return pick(rnd, ["undefined", "Infinity", "[1,]", "{,}", "\u0000", "<html>502</html>"]);
    default:
      return json.replace(/\d/, "9".repeat(400));
  }
}

interface Case {
  body: string;
  status: number;
  label: string;
}

function generateCase(rnd: Rnd, fixture: unknown): Case {
  const statusRoll = rnd();
  const status = statusRoll < 0.8 ? 200 : pick(rnd, [400, 404, 408, 422, 429, 500, 503]);
  const roll = rnd();
  if (roll < 0.7) {
    return { body: JSON.stringify(mutateValue(rnd, fixture)), status, label: "structured" };
  }
  if (roll < 0.9) {
    return { body: corruptText(rnd, JSON.stringify(fixture)), status, label: "text" };
  }
  return { body: JSON.stringify(fixture), status, label: "valid" };
}

// ── harness ──────────────────────────────────────────────────────────────────

type Outcome =
  | { kind: "ok"; value: unknown }
  | { kind: "PolicyApiError"; status: number }
  | { kind: "PolicyParseError"; path: string; reason: string }
  | { kind: "crash"; error: unknown };

function respond(c: Case): typeof fetch {
  return vi.fn<typeof fetch>(async () => new Response(c.body, { status: c.status, headers: { "content-type": "application/json" } }));
}

async function run(make: (f: typeof fetch) => PolicyClient, ep: Endpoint, c: Case): Promise<Outcome> {
  const client = make(respond(c));
  try {
    return { kind: "ok", value: await ep.call(client) };
  } catch (err) {
    if (err instanceof PolicyParseError) return { kind: "PolicyParseError", path: err.path, reason: err.reason };
    if (err instanceof PolicyApiError) return { kind: "PolicyApiError", status: err.status };
    return { kind: "crash", error: err };
  }
}

const real = (f: typeof fetch) => createPolicyClient({ apiUrl: "https://api.test", network: "testnet", fetch: f });
const parsed = (f: typeof fetch) => createParsedPolicyClient({ apiUrl: "https://api.test", network: "testnet", fetch: f });

const SEEDS = [0x5eed0001, 0x5eed0002, 0x5eed0003];
const ITERATIONS_PER_SEED = 250;

function crashSignature(err: unknown): string {
  return err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}

// ── the fuzz runs ────────────────────────────────────────────────────────────

describe("fuzz: createParsedPolicyClient never escapes a named outcome (#675)", () => {
  for (const ep of ENDPOINTS) {
    it(`${ep.name}: every adversarial body → typed value | PolicyApiError | PolicyParseError`, async () => {
      let parseErrors = 0;
      let apiErrors = 0;
      let oks = 0;
      for (const seed of SEEDS) {
        const rnd = prng(seed ^ ep.name.length);
        for (let i = 0; i < ITERATIONS_PER_SEED; i++) {
          const c = generateCase(rnd, ep.fixture);
          const out = await run(parsed, ep, c);
          const where = `${ep.name} seed=${seed.toString(16)} i=${i} status=${c.status} ${c.label} body=${c.body.slice(0, 200)}`;

          expect(out.kind, `crash at ${where}: ${out.kind === "crash" ? crashSignature(out.error) : ""}`).not.toBe("crash");

          if (c.status >= 400) {
            // A non-2xx must ALWAYS be a PolicyApiError, whatever the body is.
            expect(out.kind, where).toBe("PolicyApiError");
            apiErrors++;
            continue;
          }
          if (out.kind === "ok") {
            // The invariant that makes the type honest: what we resolved with
            // re-parses to itself, and nothing hostile is reachable on it.
            expect(ep.reparse(out.value), where).toEqual(out.value);
            expect(JSON.stringify(out.value), where).not.toContain("polluted");
            expect(Object.prototype.hasOwnProperty.call(out.value as object, "__proto__"), where).toBe(false);
            oks++;
          } else if (out.kind === "PolicyParseError") {
            expect(out.reason.length, where).toBeGreaterThan(0);
            parseErrors++;
          }
        }
      }
      // Sanity on the generator: all three outcomes were actually exercised.
      expect(oks).toBeGreaterThan(0);
      expect(parseErrors).toBeGreaterThan(0);
      expect(apiErrors).toBeGreaterThan(0);
    });
  }

  it("the global prototype was not polluted by any fuzz payload", () => {
    expect(({} as { polluted?: unknown }).polluted).toBeUndefined();
    expect(([] as { polluted?: unknown }).polluted).toBeUndefined();
  });
});

describe("fuzz: what the REAL createPolicyClient does with the same bodies (#675)", () => {
  // Every crash class the fuzzer finds in src/policy-client.ts is listed here
  // and pinned by a regression test below. If this set changes — in either
  // direction — the regression tests (not this list) are the place to update.
  const KNOWN_CRASHES = [
    /^TypeError: Cannot read properties of null \(reading 'message'\)$/, // non-2xx + `null` body
    /^TypeError: Cannot destructure property '(policy|contractId)' of /, // 2xx + `null` body on an envelope endpoint
  ];

  for (const ep of ENDPOINTS) {
    it(`${ep.name}: crashes only in the known classes; wrong-shaped 2xx bodies resolve unchecked`, async () => {
      const unknownCrashes: string[] = [];
      let unchecked = 0;
      for (const seed of SEEDS) {
        const rnd = prng(seed ^ ep.name.length);
        for (let i = 0; i < ITERATIONS_PER_SEED; i++) {
          const c = generateCase(rnd, ep.fixture);
          const out = await run(real, ep, c);
          if (out.kind === "crash") {
            const sig = crashSignature(out.error);
            if (!KNOWN_CRASHES.some((re) => re.test(sig))) {
              unknownCrashes.push(`${sig} @ seed=${seed.toString(16)} i=${i} body=${c.body.slice(0, 120)}`);
            }
          } else if (out.kind === "ok" && c.status < 400) {
            // Resolved — but does the value actually have the declared type?
            try {
              ep.reparse(out.value);
            } catch {
              unchecked++;
            }
          }
        }
      }
      expect(unknownCrashes, "a crash class the regression tests do not cover").toEqual([]);
      // This is the gap the parser closes: the real client hands back
      // mis-shaped values as if they were typed. Expected to go to 0 once
      // src/policy-client.ts parses.
      expect(unchecked).toBeGreaterThan(0);
    });
  }
});

// ── regression tests: crashes the fuzzer found, pinned ───────────────────────

describe("regression: bodies that crash src/policy-client.ts with a raw TypeError (#675)", () => {
  const nullBody = (status: number) =>
    vi.fn<typeof fetch>(async () => new Response("null", { status, headers: { "content-type": "application/json" } }));

  it("non-2xx with JSON `null` body: real client throws TypeError, parsed client throws PolicyApiError", async () => {
    for (const ep of ENDPOINTS) {
      await expect(ep.call(real(nullBody(500))), ep.name).rejects.toThrow(TypeError);
      await expect(ep.call(parsed(nullBody(500))), ep.name).rejects.toBeInstanceOf(PolicyApiError);
    }
  });

  it("2xx with JSON `null` body on an envelope endpoint: real client throws TypeError, parsed client names it", async () => {
    for (const name of ["generate", "deployInstance", "recordDeployment"]) {
      const ep = ENDPOINTS.find((e) => e.name === name)!;
      await expect(ep.call(real(nullBody(200))), name).rejects.toThrow(TypeError);
      await expect(ep.call(parsed(nullBody(200))), name).rejects.toMatchObject({
        name: "PolicyParseError",
        path: "",
        reason: expect.stringMatching(/expected an object, got null/),
      });
    }
  });

  it("2xx with JSON `null` body on a list endpoint: real client resolves null typed as an array", async () => {
    await expect(real(nullBody(200)).listTemplates()).resolves.toBeNull();
    await expect(parsed(nullBody(200)).listTemplates()).rejects.toMatchObject({
      name: "PolicyParseError",
      reason: expect.stringMatching(/expected an array, got null/),
    });
  });

  it("2xx with a string body where the template list should be: real client resolves the string", async () => {
    const f = vi.fn<typeof fetch>(async () => new Response('"spending_limit"', { status: 200 }));
    await expect(real(f).listTemplates()).resolves.toBe("spending_limit");
    await expect(parsed(f).listTemplates()).rejects.toMatchObject({
      name: "PolicyParseError",
      reason: expect.stringMatching(/expected an array, got string/),
    });
  });

  it("2xx generate with `policy` of the wrong type: real client resolves it as a GeneratedPolicy", async () => {
    const f = vi.fn<typeof fetch>(async () => new Response(JSON.stringify({ policy: ["not", "a", "policy"] }), { status: 200 }));
    await expect(real(f).generate(DEFINITION)).resolves.toEqual(["not", "a", "policy"]);
    await expect(parsed(f).generate(DEFINITION)).rejects.toMatchObject({
      name: "PolicyParseError",
      path: "policy",
      reason: expect.stringMatching(/expected an object, got array/),
    });
  });
});

// ── unit tests: happy path and named failure modes of the parser ─────────────

describe("policy response parser: happy path (#675)", () => {
  it("accepts the documented template list and returns fresh objects", () => {
    const out = parsePolicyTemplateList(TEMPLATES);
    expect(out).toEqual(TEMPLATES);
    expect(out[0]).not.toBe(TEMPLATES[0]);
  });

  it("accepts a fully populated GeneratedPolicy, including constructorArgs and instance", () => {
    expect(parseGeneratedPolicy(POLICY)).toEqual(POLICY);
  });

  it("accepts a deployed policy whose deployment record omits contractId", () => {
    const deployed = {
      ...POLICY,
      status: "deployed",
      deployment: { txHash: POLICY.instance!.txHash, deployedAt: POLICY.instance!.deployedAt },
    };
    expect(parsePolicyEnvelope({ policy: deployed }, "POST /policies/deploy")).toEqual(deployed);
  });

  it("accepts the verified-recipient constructor shape", () => {
    const t = {
      ...VALID_SPENDING_LIMIT_TEMPLATE,
      enforcement: { kind: "policy-contract", wasmHash: "ab", constructorArgs: { registry: "CREG…" } },
    };
    expect(parsePolicyTemplateList([t])[0]!.enforcement).toEqual(t.enforcement);
  });

  it("drops unknown keys instead of carrying them to the caller", () => {
    const out = parseValidationResult({ valid: true, errors: [], debug: { sql: "..." }, __proto__: { polluted: 1 } });
    expect(out).toEqual({ valid: true, errors: [] });
    expect(Object.keys(out)).toEqual(["valid", "errors"]);
  });

  it("readBody distinguishes JSON null, empty, and invalid bodies without throwing", async () => {
    await expect(readBody(new Response("null"))).resolves.toEqual({ kind: "json", value: null });
    await expect(readBody(new Response(""))).resolves.toEqual({ kind: "empty" });
    await expect(readBody(new Response("{oops"))).resolves.toMatchObject({ kind: "invalid" });
  });
});

describe("policy response parser: named failure modes (#675)", () => {
  const cases: Array<[string, () => unknown, RegExp, string]> = [
    ["wrong top-level type", () => parsePolicyTemplateList({ templates: TEMPLATES }), /expected an array, got object/, ""],
    ["missing required field", () => parseGeneratedPolicy({ ...POLICY, policyHash: undefined }), /expected a string, got undefined/, "policyHash"],
    ["bad status enum", () => parseGeneratedPolicy({ ...POLICY, status: "deployed2" }), /expected one of generated \| instance_deployed \| deployed/, "status"],
    ["bad network enum", () => parseGeneratedPolicy({ ...POLICY, manifest: { ...POLICY.manifest, network: "futurenet" } }), /expected one of testnet \| mainnet/, "manifest.network"],
    ["unknown enforcement kind", () => parsePolicyTemplateList([{ ...VALID_NO_ENFORCEMENT_TEMPLATE, enforcement: { kind: "magic" } }]), /expected one of policy-contract/, "[0].enforcement.kind"],
    ["policy-contract without wasmHash", () => parsePolicyTemplateList([{ ...VALID_NO_ENFORCEMENT_TEMPLATE, enforcement: { kind: "policy-contract" } }]), /expected a string, got undefined/, "[0].enforcement.wasmHash"],
    ["non-digit stroops", () => parseGeneratedPolicy({ ...POLICY, manifest: { ...POLICY.manifest, enforcement: { kind: "policy-contract", wasmHash: "ab", constructorArgs: { dailyLimitStroops: "1e9", windowSeconds: 1 } } } }), /decimal digit string/, "manifest.enforcement.constructorArgs.dailyLimitStroops"],
    ["owners not strings", () => parseGeneratedPolicy({ ...POLICY, definition: { ...DEFINITION, owners: ["G…", 42] } }), /expected a string, got number 42/, "definition.owners[1]"],
    ["threshold negative", () => parseGeneratedPolicy({ ...POLICY, definition: { ...DEFINITION, threshold: -1 } }), /non-negative integer/, "definition.threshold"],
    ["createdAt not a timestamp", () => parseGeneratedPolicy({ ...POLICY, createdAt: "yesterday" }), /ISO-8601/, "createdAt"],
    ["status says deployed but no record", () => parseGeneratedPolicy({ ...POLICY, status: "deployed" }), /no deployment record/, "deployment"],
    ["valid:true with errors", () => parseValidationResult({ valid: true, errors: ["x"] }), /valid is true but errors is non-empty/, "errors"],
    ["simulate ok not boolean", () => parseSimulateResult({ ok: "true" }), /expected a boolean, got string/, "ok"],
    ["envelope without policy", () => parsePolicyEnvelope({ data: POLICY }, "POST /policies/generate"), /missing/, "policy"],
  ];

  it.each(cases)("%s → PolicyParseError", (_label, fn, reason, path) => {
    let caught: unknown;
    try {
      fn();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(PolicyParseError);
    const e = caught as PolicyParseError;
    expect(e.name).toBe("PolicyParseError");
    expect(e.reason).toMatch(reason);
    expect(e.path).toBe(path);
    expect(e.message).toContain(e.endpoint);
    expect(isNamedPolicyError(e)).toBe(true);
  });

  it("a nesting bomb is a PolicyParseError, not a RangeError", () => {
    let bomb: unknown = "x";
    for (let i = 0; i < 100_000; i++) bomb = [bomb];
    expect(() => parsePolicyTemplateList(bomb)).toThrow(PolicyParseError);
    expect(() => parsePolicyTemplateList(bomb)).toThrow(/nests deeper than/);
  });

  it("a node bomb is a PolicyParseError", () => {
    const wide = Array.from({ length: 60_000 }, () => 0);
    expect(() => parseValidationResult({ valid: true, errors: wide })).toThrow(/more than 50000 nodes/);
  });

  it("hostile key names never reach the parsed object or the global prototype", () => {
    const hostile = JSON.parse('{"valid":true,"errors":[],"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}');
    const out = parseValidationResult(hostile);
    expect(out).toEqual({ valid: true, errors: [] });
    expect(({} as { polluted?: unknown }).polluted).toBeUndefined();
  });
});

// ── request parity: the parsed client must send exactly what the real one sends

describe("createParsedPolicyClient sends the same requests as createPolicyClient (#675)", () => {
  function recorder() {
    const calls: Array<{ url: string; method: string; body: unknown }> = [];
    const f = vi.fn<typeof fetch>(async (url, init) => {
      calls.push({
        url: String(url),
        method: init?.method ?? "GET",
        body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      });
      return new Response("{}", { status: 500 });
    });
    return { f, calls };
  }

  it.each(ENDPOINTS.map((e) => [e.name, e] as const))("%s", async (_name, ep) => {
    const a = recorder();
    const b = recorder();
    await ep.call(real(a.f)).catch(() => undefined);
    await ep.call(parsed(b.f)).catch(() => undefined);
    expect(b.calls).toEqual(a.calls);
    expect(a.calls).toHaveLength(1);
  });
});
