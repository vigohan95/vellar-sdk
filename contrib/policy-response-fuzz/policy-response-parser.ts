// Typed parsing of policy-service responses (issue #675).
//
// WHAT THE FUZZER FOUND: `src/policy-client.ts` has no parser. `req<T>` does
// `(await res.json().catch(() => ({}))) as T` and returns whatever the gateway
// sent, so a malformed template list or generate response flows into callers
// with a type it does not have. Two body shapes crash it outright with a raw
// `TypeError` instead of a named error:
//
//   - any non-2xx response whose JSON body is the literal `null`
//     (`payload.message` on null, src/policy-client.ts:101), and
//   - a 2xx `null` body on `generate` / `deployInstance` / `recordDeployment`
//     (destructuring `{ policy }` / `{ contractId }` from null).
//
// Everything else that is wrong-but-valid JSON (a string where the template
// list should be, `status: "deployed2"`, `manifest.network: "futurenet"`, a
// `policy` that is an array) resolves successfully and is handed to the caller
// as a `GeneratedPolicy` / `PolicyTemplateInfo[]`.
//
// This module is the reference fix: one named error (`PolicyParseError`), one
// structural parser per response shape, and a drop-in `PolicyClient` that runs
// them. The parsers build fresh objects from known fields — they never spread
// or return the raw payload — so `__proto__` / `constructor` keys in a hostile
// body cannot reach a caller, and they are depth-bounded so a nesting bomb is a
// parse error, not a `RangeError`.
//
// Same posture as contrib/policy-template-validation.ts and the #448 client-side
// validator: structural checks the client can make locally; the server remains
// authoritative on semantics.

import type { PolicyDefinition } from "../../src/types";
import {
  PolicyApiError,
  type Enforcement,
  type GeneratedPolicy,
  type PolicyTemplateInfo,
  type SimulateResult,
  type ValidationResult,
} from "../../src/policy-types";
import {
  PolicyListFilterError,
  type PolicyClient,
  type PolicyClientOptions,
  type PolicyListFilters,
} from "../../src/policy-client";

// ── the named error ──────────────────────────────────────────────────────────

/**
 * A policy-service response did not have the documented shape. Carries WHERE
 * (`endpoint` + JSON `path`) and WHY (`reason`) so a caller or a log can say
 * precisely what the gateway sent, without the caller having to inspect the
 * body itself.
 *
 * Distinct from `PolicyApiError` on purpose: that one means "the gateway said
 * no" (non-2xx, or transport failure); this one means "the gateway said yes,
 * but what it sent back is not a policy response".
 */
export class PolicyParseError extends Error {
  readonly endpoint: string;
  /** Dotted path into the body, e.g. `manifest.network` or `[2].enforcement`. */
  readonly path: string;
  readonly reason: string;

  constructor(endpoint: string, path: string, reason: string) {
    super(`${endpoint}: malformed response at ${path || "<root>"}: ${reason}`);
    this.name = "PolicyParseError";
    this.endpoint = endpoint;
    this.path = path;
    this.reason = reason;
  }
}

// ── bounds ───────────────────────────────────────────────────────────────────

/** Deeper than any documented policy response (max real depth is 3). */
export const MAX_RESPONSE_DEPTH = 16;
/** More nodes than any documented policy response could legitimately carry. */
export const MAX_RESPONSE_NODES = 50_000;

/**
 * Iterative (no recursion) walk that rejects a body that is too deep or too
 * large BEFORE any field is read. Works on the parsed value, so it also bounds
 * what a lenient `JSON.parse` already accepted.
 */
export function assertBounded(endpoint: string, value: unknown): void {
  let nodes = 0;
  const stack: Array<{ v: unknown; d: number; p: string }> = [{ v: value, d: 0, p: "" }];
  while (stack.length > 0) {
    const { v, d, p } = stack.pop()!;
    nodes++;
    if (nodes > MAX_RESPONSE_NODES) {
      throw new PolicyParseError(endpoint, p, `body has more than ${MAX_RESPONSE_NODES} nodes`);
    }
    if (d > MAX_RESPONSE_DEPTH) {
      throw new PolicyParseError(endpoint, p, `body nests deeper than ${MAX_RESPONSE_DEPTH} levels`);
    }
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) stack.push({ v: v[i], d: d + 1, p: `${p}[${i}]` });
    } else if (typeof v === "object" && v !== null) {
      for (const k of Object.keys(v)) {
        stack.push({ v: (v as Record<string, unknown>)[k], d: d + 1, p: p ? `${p}.${k}` : k });
      }
    }
  }
}

// ── field readers ────────────────────────────────────────────────────────────

type Obj = Record<string, unknown>;

function describe(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "string") return `string ${JSON.stringify(v.length > 40 ? v.slice(0, 40) + "…" : v)}`;
  if (typeof v === "object") return "object";
  return `${typeof v} ${String(v)}`;
}

function join(path: string, key: string): string {
  return path ? `${path}.${key}` : key;
}

class Reader {
  constructor(private readonly endpoint: string) {}

  fail(path: string, reason: string): never {
    throw new PolicyParseError(this.endpoint, path, reason);
  }

  /** A plain object — not null, not an array. Own `__proto__` is tolerated on
   * input (JSON.parse creates it as an ordinary own property) but is never
   * copied out, because every parser below picks fields by name. */
  object(v: unknown, path: string): Obj {
    if (typeof v !== "object" || v === null || Array.isArray(v)) {
      this.fail(path, `expected an object, got ${describe(v)}`);
    }
    return v as Obj;
  }

  array(v: unknown, path: string): unknown[] {
    if (!Array.isArray(v)) this.fail(path, `expected an array, got ${describe(v)}`);
    return v;
  }

  string(v: unknown, path: string, opts: { nonEmpty?: boolean } = { nonEmpty: true }): string {
    if (typeof v !== "string") this.fail(path, `expected a string, got ${describe(v)}`);
    if (opts.nonEmpty && v.length === 0) this.fail(path, "expected a non-empty string");
    return v;
  }

  optionalString(v: unknown, path: string): string | undefined {
    return v === undefined ? undefined : this.string(v, path, { nonEmpty: false });
  }

  boolean(v: unknown, path: string): boolean {
    if (typeof v !== "boolean") this.fail(path, `expected a boolean, got ${describe(v)}`);
    return v;
  }

  finiteNumber(v: unknown, path: string): number {
    if (typeof v !== "number" || !Number.isFinite(v)) {
      this.fail(path, `expected a finite number, got ${describe(v)}`);
    }
    return v;
  }

  nonNegativeInteger(v: unknown, path: string): number {
    const n = this.finiteNumber(v, path);
    if (!Number.isInteger(n) || n < 0) this.fail(path, `expected a non-negative integer, got ${n}`);
    return n;
  }

  /** Decimal digits only — the same rule parseAmount applies to x402 amounts. */
  digitString(v: unknown, path: string): string {
    const s = this.string(v, path);
    if (!/^\d+$/.test(s)) this.fail(path, `expected a decimal digit string, got ${describe(v)}`);
    return s;
  }

  timestamp(v: unknown, path: string): string {
    const s = this.string(v, path);
    if (Number.isNaN(Date.parse(s))) this.fail(path, `expected an ISO-8601 timestamp, got ${describe(v)}`);
    return s;
  }

  oneOf<T extends string>(v: unknown, path: string, allowed: readonly T[]): T {
    if (typeof v !== "string" || !(allowed as readonly string[]).includes(v)) {
      this.fail(path, `expected one of ${allowed.join(" | ")}, got ${describe(v)}`);
    }
    return v as T;
  }

  stringArray(v: unknown, path: string): string[] {
    return this.array(v, path).map((item, i) => this.string(item, `${path}[${i}]`));
  }
}

// ── shape parsers (pure) ─────────────────────────────────────────────────────

const POLICY_STATUSES = ["generated", "instance_deployed", "deployed"] as const;
const NETWORKS = ["testnet", "mainnet"] as const;

export function parseEnforcement(r: Reader, v: unknown, path: string): Enforcement {
  const o = r.object(v, path);
  const kind = r.oneOf(o.kind, join(path, "kind"), [
    "policy-contract",
    "signer-limits",
    "none",
    "custom-contract-pending",
  ] as const);
  if (kind !== "policy-contract") return { kind };

  const wasmHash = r.string(o.wasmHash, join(path, "wasmHash"));
  if (o.constructorArgs === undefined) return { kind, wasmHash };

  const argsPath = join(path, "constructorArgs");
  const args = r.object(o.constructorArgs, argsPath);
  if ("registry" in args) {
    return { kind, wasmHash, constructorArgs: { registry: r.string(args.registry, join(argsPath, "registry")) } };
  }
  if ("dailyLimitStroops" in args || "windowSeconds" in args) {
    return {
      kind,
      wasmHash,
      constructorArgs: {
        dailyLimitStroops: r.digitString(args.dailyLimitStroops, join(argsPath, "dailyLimitStroops")),
        windowSeconds: r.nonNegativeInteger(args.windowSeconds, join(argsPath, "windowSeconds")),
      },
    };
  }
  return r.fail(argsPath, "expected SpendingConstructor or VerifiedRecipientConstructor fields");
}

function parseTemplate(r: Reader, v: unknown, path: string): PolicyTemplateInfo {
  const o = r.object(v, path);
  return {
    type: r.string(o.type, join(path, "type")),
    title: r.string(o.title, join(path, "title")),
    description: r.string(o.description, join(path, "description"), { nonEmpty: false }),
    enforcement: parseEnforcement(r, o.enforcement, join(path, "enforcement")),
  };
}

/** GET /policies/templates */
export function parsePolicyTemplateList(raw: unknown, endpoint = "GET /policies/templates"): PolicyTemplateInfo[] {
  assertBounded(endpoint, raw);
  const r = new Reader(endpoint);
  return r.array(raw, "").map((t, i) => parseTemplate(r, t, `[${i}]`));
}

/**
 * Structural PolicyDefinition check. Deliberately NOT the #448 semantic
 * validator (contrib/wave-447-448-449-450/policy-validation.ts): that one fixes
 * a type vocabulary (`spending-limit`) that differs from the fixtures the SDK's
 * own tests use (`spending_limit`), and a response parser must accept whatever
 * type string the server generated — it is the server's definition echoed back.
 */
export function parsePolicyDefinition(r: Reader, v: unknown, path: string): PolicyDefinition {
  const o = r.object(v, path);
  const out: PolicyDefinition = {
    version: r.string(o.version, join(path, "version")),
    type: r.string(o.type, join(path, "type")),
    owners: r.stringArray(o.owners, join(path, "owners")),
  };
  if (o.threshold !== undefined) out.threshold = r.nonNegativeInteger(o.threshold, join(path, "threshold"));
  if (o.spendingLimits !== undefined) {
    const p = join(path, "spendingLimits");
    const s = r.object(o.spendingLimits, p);
    out.spendingLimits = {};
    const daily = r.optionalString(s.dailyXlm, join(p, "dailyXlm"));
    const perTx = r.optionalString(s.perTxXlm, join(p, "perTxXlm"));
    if (daily !== undefined) out.spendingLimits.dailyXlm = daily;
    if (perTx !== undefined) out.spendingLimits.perTxXlm = perTx;
  }
  if (o.allowlistedContracts !== undefined) {
    out.allowlistedContracts = r.stringArray(o.allowlistedContracts, join(path, "allowlistedContracts"));
  }
  if (o.timelocks !== undefined) {
    const p = join(path, "timelocks");
    const t = r.object(o.timelocks, p);
    out.timelocks = {};
    if (t.adminActionDelaySeconds !== undefined) {
      out.timelocks.adminActionDelaySeconds = r.nonNegativeInteger(
        t.adminActionDelaySeconds,
        join(p, "adminActionDelaySeconds"),
      );
    }
  }
  return out;
}

/** A bare GeneratedPolicy (one element of GET /policies, or the `policy` of an envelope). */
export function parseGeneratedPolicy(raw: unknown, endpoint = "policy", path = ""): GeneratedPolicy {
  assertBounded(endpoint, raw);
  const r = new Reader(endpoint);
  const o = r.object(raw, path);

  const manifestPath = join(path, "manifest");
  const m = r.object(o.manifest, manifestPath);

  const out: GeneratedPolicy = {
    id: r.string(o.id, join(path, "id")),
    createdAt: r.timestamp(o.createdAt, join(path, "createdAt")),
    status: r.oneOf(o.status, join(path, "status"), POLICY_STATUSES),
    definition: parsePolicyDefinition(r, o.definition, join(path, "definition")),
    policyHash: r.string(o.policyHash, join(path, "policyHash")),
    manifest: {
      template: r.string(m.template, join(manifestPath, "template")),
      enforcement: parseEnforcement(r, m.enforcement, join(manifestPath, "enforcement")),
      network: r.oneOf(m.network, join(manifestPath, "network"), NETWORKS),
    },
  };

  if (o.instance !== undefined) {
    const p = join(path, "instance");
    const i = r.object(o.instance, p);
    out.instance = {
      contractId: r.string(i.contractId, join(p, "contractId")),
      txHash: r.string(i.txHash, join(p, "txHash")),
      deployedAt: r.timestamp(i.deployedAt, join(p, "deployedAt")),
    };
  }
  if (o.deployment !== undefined) {
    const p = join(path, "deployment");
    const d = r.object(o.deployment, p);
    out.deployment = {
      txHash: r.string(d.txHash, join(p, "txHash")),
      deployedAt: r.timestamp(d.deployedAt, join(p, "deployedAt")),
    };
    const contractId = r.optionalString(d.contractId, join(p, "contractId"));
    if (contractId !== undefined) out.deployment.contractId = contractId;
  }
  // Status/field consistency is checkable locally and a mismatch is exactly the
  // kind of half-written record a caller would otherwise act on.
  if (out.status === "deployed" && !out.deployment) {
    r.fail(join(path, "deployment"), 'status is "deployed" but no deployment record is present');
  }
  if (out.status === "instance_deployed" && !out.instance) {
    r.fail(join(path, "instance"), 'status is "instance_deployed" but no instance record is present');
  }
  return out;
}

/** GET /policies */
export function parseGeneratedPolicyList(raw: unknown, endpoint = "GET /policies"): GeneratedPolicy[] {
  assertBounded(endpoint, raw);
  const r = new Reader(endpoint);
  return r.array(raw, "").map((p, i) => parseGeneratedPolicy(p, endpoint, `[${i}]`));
}

/** POST /policies/generate and POST /policies/deploy both answer `{ policy }`. */
export function parsePolicyEnvelope(raw: unknown, endpoint: string): GeneratedPolicy {
  assertBounded(endpoint, raw);
  const r = new Reader(endpoint);
  const o = r.object(raw, "");
  if (o.policy === undefined) r.fail("policy", "missing");
  return parseGeneratedPolicy(o.policy, endpoint, "policy");
}

/** POST /policies/validate */
export function parseValidationResult(raw: unknown, endpoint = "POST /policies/validate"): ValidationResult {
  assertBounded(endpoint, raw);
  const r = new Reader(endpoint);
  const o = r.object(raw, "");
  const valid = r.boolean(o.valid, "valid");
  const errors = r.stringArray(o.errors, "errors");
  if (valid && errors.length > 0) r.fail("errors", "valid is true but errors is non-empty");
  return { valid, errors };
}

/** POST /policies/:id/simulate */
export function parseSimulateResult(raw: unknown, endpoint = "POST /policies/:id/simulate"): SimulateResult {
  assertBounded(endpoint, raw);
  const r = new Reader(endpoint);
  const o = r.object(raw, "");
  const out: SimulateResult = { ok: r.boolean(o.ok, "ok") };
  if (o.minResourceFee !== undefined) out.minResourceFee = r.digitString(o.minResourceFee, "minResourceFee");
  if (o.error !== undefined) out.error = r.string(o.error, "error", { nonEmpty: false });
  return out;
}

/** POST /policies/:id/deploy-instance */
export function parseDeployInstanceResult(
  raw: unknown,
  endpoint = "POST /policies/:id/deploy-instance",
): { contractId: string } {
  assertBounded(endpoint, raw);
  const r = new Reader(endpoint);
  const o = r.object(raw, "");
  return { contractId: r.string(o.contractId, "contractId") };
}

/**
 * The non-2xx body. Tolerant by design — an error body is allowed to be
 * anything, and the point is to surface the gateway's message if there is one,
 * never to throw while building an error.
 */
export function parseErrorEnvelope(raw: unknown): { message?: string; error?: string; errors?: string[] } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};
  const o = raw as Obj;
  const out: { message?: string; error?: string; errors?: string[] } = {};
  if (typeof o.message === "string") out.message = o.message;
  if (typeof o.error === "string") out.error = o.error;
  if (Array.isArray(o.errors)) out.errors = o.errors.filter((e): e is string => typeof e === "string");
  return out;
}

// ── a PolicyClient that parses ───────────────────────────────────────────────

/**
 * Same surface and same requests as `createPolicyClient` (the parity test pins
 * URL, method and body for every method), but the RESPONSE side is replaced: a
 * method resolves with a value that HAS the declared type, or rejects with
 * `PolicyApiError` (gateway said no / transport failed) or `PolicyParseError`
 * (gateway said yes with a malformed body). Nothing else escapes — see the fuzz
 * harness for the proof.
 *
 * The request side is duplicated rather than delegated because the two crashes
 * the fuzzer found happen inside the real `req` before any wrapper could see
 * the value (`payload.message` on a null body; `{ policy }` destructured from
 * null). Once src/policy-client.ts adopts `readBody` below, this file reduces to
 * the parsers.
 */
export function createParsedPolicyClient(options: PolicyClientOptions): PolicyClient {
  const base = options.apiUrl.replace(/\/+$/, "");
  const doFetch = options.fetch ?? fetch;

  async function req<T>(
    endpoint: string,
    path: string,
    init: RequestInit | undefined,
    parse: (raw: unknown, endpoint: string) => T,
  ): Promise<T> {
    let res: Response;
    try {
      res = await doFetch(`${base}/policies${path}`, {
        headers: init?.body ? { "content-type": "application/json" } : undefined,
        ...init,
      });
    } catch (err) {
      throw new PolicyApiError(err instanceof Error ? err.message : "network request failed", 0);
    }
    const body = await readBody(res);
    if (!res.ok) {
      // An error body may be anything; never throw while building the error.
      const env = parseErrorEnvelope(body.kind === "json" ? body.value : undefined);
      throw new PolicyApiError(
        env.message ?? env.error ?? `Request failed (${res.status})`,
        res.status,
        env.errors,
      );
    }
    if (body.kind === "empty") throw new PolicyParseError(endpoint, "", "2xx response with an empty body");
    if (body.kind === "invalid") throw new PolicyParseError(endpoint, "", `2xx response body is not JSON: ${body.reason}`);
    return parse(body.value, endpoint);
  }

  return {
    listTemplates: () => req("GET /policies/templates", "/templates", undefined, parsePolicyTemplateList),
    listPolicies: (filters) => req("GET /policies", buildListQuery(filters), undefined, parseGeneratedPolicyList),
    validate: (definition) =>
      req("POST /policies/validate", "/validate", { method: "POST", body: JSON.stringify(definition) }, parseValidationResult),
    generate: (definition) =>
      req(
        "POST /policies/generate",
        "/generate",
        { method: "POST", body: JSON.stringify({ definition, network: options.network }) },
        parsePolicyEnvelope,
      ),
    simulate: (policyId, wallet) =>
      req(`POST /policies/${policyId}/simulate`, `/${policyId}/simulate`, { method: "POST", body: JSON.stringify({ wallet }) }, parseSimulateResult),
    deployInstance: (policyId, wallet) =>
      req(
        `POST /policies/${policyId}/deploy-instance`,
        `/${policyId}/deploy-instance`,
        { method: "POST", body: JSON.stringify({ wallet }) },
        parseDeployInstanceResult,
      ),
    recordDeployment: (policyId, txHash, contractId) =>
      req(
        "POST /policies/deploy",
        "/deploy",
        { method: "POST", body: JSON.stringify({ policyId, txHash, contractId }) },
        parsePolicyEnvelope,
      ),
  };
}

/** Mirrors the real client's list-filter query (including its date check). */
function buildListQuery(filters?: PolicyListFilters): string {
  if (!filters) return "";
  const params = new URLSearchParams();
  if (filters.status) params.set("status", filters.status);
  if (filters.createdAfter) {
    if (Number.isNaN(Date.parse(filters.createdAfter))) {
      throw new PolicyListFilterError(`invalid created_after: ${filters.createdAfter}`);
    }
    params.set("created_after", filters.createdAfter);
  }
  if (filters.createdBefore) {
    if (Number.isNaN(Date.parse(filters.createdBefore))) {
      throw new PolicyListFilterError(`invalid created_before: ${filters.createdBefore}`);
    }
    params.set("created_before", filters.createdBefore);
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

export type ResponseBody =
  | { kind: "json"; value: unknown }
  | { kind: "empty" }
  | { kind: "invalid"; reason: string };

/**
 * Read a body without ever throwing. Distinguishes the three things a gateway
 * can send — valid JSON (including the literal `null`), nothing, or bytes that
 * are not JSON — because they need different handling: only the first can be
 * parsed, and only the first can carry an error message.
 */
export async function readBody(res: Response): Promise<ResponseBody> {
  let text: string;
  try {
    text = await res.text();
  } catch (err) {
    return { kind: "invalid", reason: `body could not be read: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (text.length === 0) return { kind: "empty" };
  try {
    return { kind: "json", value: JSON.parse(text) };
  } catch (err) {
    return { kind: "invalid", reason: err instanceof Error ? err.message : String(err) };
  }
}

/** True when `err` is one of the two outcomes a policy call is allowed to reject with. */
export function isNamedPolicyError(err: unknown): err is PolicyApiError | PolicyParseError {
  return err instanceof PolicyApiError || err instanceof PolicyParseError;
}
