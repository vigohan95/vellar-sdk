// No-secrets-in-errors contract for WalletApiError (issue #674).
//
// THE CONTRACT (belongs above `WalletApiError` in src/http-backend.ts):
//
//   A WalletApiError — its `message`, `code`, `stack`, `String(err)` and
//   `JSON.stringify(err)` — must never contain any fragment of a request field
//   that is secret-bearing: the signed transaction envelope (`signedXdr`,
//   `signedTx`), the passkey credential id (`keyId`), or any session token.
//   Errors are logged, shipped to crash reporters and shown in UIs; a signed
//   envelope in a log line is a replayable payment, and a credential id ties a
//   log line to a passkey.
//
// WHAT HOLDS TODAY: the SDK itself never puts request fields into the error.
// `toApiError` builds the message from the RESPONSE (`payload.message` /
// `payload.error`) or a fixed string, and `JSON.stringify(err)` exposes only
// `status` and `code` (Error's own `message` is non-enumerable). The tests
// prove that for all three endpoints and every error-body shape.
//
// THE GAP: the message is the gateway's text VERBATIM. A gateway (or a
// validation framework in front of it) that echoes the offending field —
// `"invalid envelope: AAAAAgAAAAD…"` — turns the SDK error into a carrier for
// the very XDR the contract forbids, and `code` is the same story for
// `payload.error`. The SDK cannot stop a server from echoing; what it CAN do
// is refuse to repeat the echo. `createRedactingHttpWalletBackend` below is
// that refusal: it knows the request it just sent, so it can strip any
// fragment of the secret-bearing fields from the error before the caller
// sees it. Same approach as the MCP payer's output.ts and the #451 CLI
// redactor: exact-match registry, applied at the boundary.

import {
  createHttpWalletBackend,
  WalletApiError,
  type HttpWalletBackend,
} from "../../src/http-backend";
import { defaultSignedToXdr } from "../../src/passkeykit-connector";

/** Request fields whose values must never appear in an error. */
export const SECRET_BEARING_REQUEST_FIELDS = ["signedXdr", "signedTx", "keyId"] as const;
export type SecretBearingField = (typeof SECRET_BEARING_REQUEST_FIELDS)[number];

/**
 * Shortest substring of a secret that counts as a leak. 12 base64 characters
 * is 72 bits of a random envelope — a coincidental overlap with English error
 * text is not credible — while a server that echoes "the first 16 characters"
 * for context is still caught.
 */
export const FRAGMENT_WINDOW = 12;

const REDACTED = (field: string) => `[redacted:${field}]`;

/** A secret in the three encodings a server is likely to echo it in. */
export function secretForms(secret: string): string[] {
  const forms = new Set<string>([secret]);
  const hex = base64ToHex(secret);
  if (hex) forms.add(hex);
  forms.add(secret.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")); // base64url
  return [...forms].filter((f) => f.length >= FRAGMENT_WINDOW);
}

function base64ToHex(s: string): string | undefined {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length % 4 !== 0) return undefined;
  try {
    const bin = atob(s);
    let hex = "";
    for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, "0");
    return hex;
  } catch {
    return undefined;
  }
}

/**
 * Every window of `FRAGMENT_WINDOW` chars of `secret` (in any form) that
 * occurs in `haystack`. Empty array ⇒ no fragment leaked. Exported so a test
 * elsewhere can reuse the detector instead of re-deriving the rule.
 */
export function findSecretFragments(haystack: string, secret: string): string[] {
  const found = new Set<string>();
  if (!haystack) return [];
  for (const form of secretForms(secret)) {
    for (let i = 0; i + FRAGMENT_WINDOW <= form.length; i++) {
      const window = form.slice(i, i + FRAGMENT_WINDOW);
      if (haystack.includes(window)) {
        found.add(window);
        break; // one hit per form is enough evidence
      }
    }
  }
  return [...found];
}

/**
 * Every string surface an error can leak through. `stack` carries the message
 * on its first line; `json` is what a logger that `JSON.stringify`s errors
 * ships; `ownProps` is what `util.inspect`-style loggers and `{ ...err }` see.
 */
export function errorSurfaces(err: unknown): Record<string, string> {
  const e = err as Error & Record<string, unknown>;
  const own: Record<string, unknown> = {};
  for (const k of Object.getOwnPropertyNames(e)) own[k] = e[k];
  return {
    message: typeof e?.message === "string" ? e.message : "",
    toString: safeString(() => String(err)),
    stack: typeof e?.stack === "string" ? e.stack : "",
    json: safeString(() => JSON.stringify(err)),
    ownProps: safeString(() => JSON.stringify(own)),
    cause: e?.cause !== undefined ? safeString(() => String(e.cause)) : "",
  };
}

function safeString(f: () => string | undefined): string {
  try {
    return f() ?? "";
  } catch {
    return "";
  }
}

export interface LeakFinding {
  surface: string;
  field: string;
  fragment: string;
}

/** All (surface, field) pairs through which a fragment of a secret escapes. */
export function findLeaks(err: unknown, secrets: Partial<Record<string, string>>): LeakFinding[] {
  const findings: LeakFinding[] = [];
  const surfaces = errorSurfaces(err);
  for (const [field, secret] of Object.entries(secrets)) {
    if (!secret) continue;
    for (const [surface, text] of Object.entries(surfaces)) {
      for (const fragment of findSecretFragments(text, secret)) findings.push({ surface, field, fragment });
    }
  }
  return findings;
}

// ── the redaction ────────────────────────────────────────────────────────────

/**
 * Replace every run of `FRAGMENT_WINDOW` or more consecutive characters of a
 * secret (in any of its forms) with `[redacted:<field>]`. Each hit is extended
 * to the longest matching run, so a whole echoed envelope collapses to one
 * marker and a partial echo ("the first 20 characters") is removed in full.
 */
export function redactSecrets(text: string, secrets: Partial<Record<string, string>>): { text: string; fields: string[] } {
  let out = text;
  const fields = new Set<string>();
  for (const [field, secret] of Object.entries(secrets)) {
    if (!secret) continue;
    for (const form of secretForms(secret)) {
      let i = 0;
      while (i + FRAGMENT_WINDOW <= form.length) {
        if (!out.includes(form.slice(i, i + FRAGMENT_WINDOW))) {
          i++;
          continue;
        }
        let end = i + FRAGMENT_WINDOW;
        while (end < form.length && out.includes(form.slice(i, end + 1))) end++;
        out = out.split(form.slice(i, end)).join(REDACTED(field));
        fields.add(field);
        // Do NOT advance: a shorter run starting at the same offset (a partial
        // echo next to a full one) may remain; the loop re-checks this window
        // and moves on only when no run starts here. Each pass removes at
        // least one occurrence, so it terminates.
      }
    }
  }
  return { text: out, fields: [...fields] };
}

/** A WalletApiError whose message/code were scrubbed of request secrets. */
export class RedactedWalletApiError extends WalletApiError {
  /** Which request fields had fragments removed (empty ⇒ nothing was echoed). */
  readonly redactedFields: readonly string[];

  constructor(message: string, status: number, code: string | undefined, redactedFields: readonly string[]) {
    super(message, status, code);
    this.name = "WalletApiError"; // still reads as the documented class
    this.redactedFields = redactedFields;
  }
}

export function redactWalletApiError(err: WalletApiError, secrets: Partial<Record<string, string>>): RedactedWalletApiError {
  const message = redactSecrets(err.message, secrets);
  const code = err.code === undefined ? { text: undefined, fields: [] } : redactSecrets(err.code, secrets);
  const fields = [...new Set([...message.fields, ...code.fields])];
  return new RedactedWalletApiError(message.text, err.status, code.text, fields);
}

/**
 * `createHttpWalletBackend` with the no-secrets-in-errors contract enforced at
 * the boundary. Request construction is the real backend's; only a thrown
 * `WalletApiError` is intercepted, and only its `message` / `code` are
 * rewritten. Status, class and `instanceof WalletApiError` are preserved.
 */
export function createRedactingHttpWalletBackend(
  apiUrl: string,
  fetchImpl?: typeof fetch,
): HttpWalletBackend {
  const inner = fetchImpl ? createHttpWalletBackend(apiUrl, fetchImpl) : createHttpWalletBackend(apiUrl);

  async function guarded<T>(secrets: Partial<Record<SecretBearingField, string>>, run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (err) {
      if (err instanceof WalletApiError) throw redactWalletApiError(err, secrets);
      throw err;
    }
  }

  return {
    submitWalletCreation(input) {
      // Same conversion the inner backend applies, so the registered secret is
      // the exact string that went on the wire.
      let signedTx: string | undefined;
      try {
        signedTx = defaultSignedToXdr(input.signedTx);
      } catch {
        signedTx = undefined; // inner call will throw the same TypeError
      }
      return guarded({ keyId: input.keyId, signedTx }, () => inner.submitWalletCreation(input));
    },
    lookupContractId(input) {
      return guarded({ keyId: input.keyId }, () => inner.lookupContractId(input));
    },
    submitTransaction(input) {
      return guarded({ signedXdr: input.signedXdr }, () => inner.submitTransaction(input));
    },
  };
}
