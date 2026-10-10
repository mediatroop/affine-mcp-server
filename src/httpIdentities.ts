import { createHash, timingSafeEqual } from "node:crypto";
import fs from "node:fs";

/**
 * Per-caller HTTP identity for bearer mode.
 *
 * Each identity maps one HTTP bearer token to its own AFFiNE credentials, so a
 * single HTTP server can serve several people while every write lands in AFFiNE
 * under the caller's own account. Identities are loaded once at startup from
 * `AFFINE_MCP_IDENTITIES` (inline JSON) or `AFFINE_MCP_IDENTITIES_FILE` (path to
 * a JSON document). Both accept either an array of identity objects or an
 * object of `{ "<name>": { ...identity } }`.
 */
export type HttpIdentity = {
  name: string;
  token: string;
  email?: string;
  password?: string;
  apiToken?: string;
  cookie?: string;
  workspaceId?: string;
};

export const IDENTITIES_ENV = "AFFINE_MCP_IDENTITIES";
export const IDENTITIES_FILE_ENV = "AFFINE_MCP_IDENTITIES_FILE";

const MIN_TOKEN_LENGTH = 16;
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function fail(message: string): never {
  throw new Error(`Invalid ${IDENTITIES_ENV}: ${message}`);
}

function optionalString(raw: unknown, field: string, name: string): string | undefined {
  if (raw === undefined || raw === null || raw === "") return undefined;
  if (typeof raw !== "string") fail(`identity "${name}" field "${field}" must be a string.`);
  return raw;
}

function normalizeIdentity(raw: unknown, fallbackName: string | undefined, index: number): HttpIdentity {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    fail(`entry ${index} must be an object.`);
  }
  const record = raw as Record<string, unknown>;
  const nameRaw = record.name ?? fallbackName;
  if (typeof nameRaw !== "string" || !NAME_PATTERN.test(nameRaw)) {
    fail(
      `entry ${index} needs a "name" of 1-64 characters: letters, digits, ".", "_", "-".`,
    );
  }
  const name = nameRaw;
  const token = record.token;
  if (typeof token !== "string" || token.trim().length < MIN_TOKEN_LENGTH) {
    fail(`identity "${name}" needs a "token" of at least ${MIN_TOKEN_LENGTH} characters.`);
  }
  if (token !== token.trim()) {
    fail(`identity "${name}" token must not have surrounding whitespace.`);
  }

  const email = optionalString(record.email, "email", name);
  const password = optionalString(record.password, "password", name);
  const apiToken = optionalString(record.apiToken, "apiToken", name);
  const cookie = optionalString(record.cookie, "cookie", name);
  const workspaceId = optionalString(record.workspaceId, "workspaceId", name);

  if (Boolean(email) !== Boolean(password)) {
    fail(`identity "${name}" must set "email" and "password" together.`);
  }
  if (!email && !apiToken && !cookie) {
    fail(`identity "${name}" needs AFFiNE credentials: email+password, apiToken, or cookie.`);
  }

  return { name, token, email, password, apiToken, cookie, workspaceId };
}

export function parseHttpIdentities(source: string, label = IDENTITIES_ENV): HttpIdentity[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid ${label}: not valid JSON (${detail}).`);
  }

  let entries: Array<[string | undefined, unknown]>;
  if (Array.isArray(parsed)) {
    entries = parsed.map((entry) => [undefined, entry]);
  } else if (parsed && typeof parsed === "object") {
    entries = Object.entries(parsed as Record<string, unknown>);
  } else {
    throw new Error(`Invalid ${label}: expected a JSON array or object of identities.`);
  }

  const identities = entries.map(([key, entry], index) => normalizeIdentity(entry, key, index));

  const names = new Set<string>();
  const tokenDigests = new Set<string>();
  for (const identity of identities) {
    const lowerName = identity.name.toLowerCase();
    if (names.has(lowerName)) fail(`duplicate identity name "${identity.name}".`);
    names.add(lowerName);
    const digest = createHash("sha256").update(identity.token, "utf8").digest("hex");
    if (tokenDigests.has(digest)) fail(`identity "${identity.name}" reuses another identity's token.`);
    tokenDigests.add(digest);
  }
  return identities;
}

/** Load identities from the environment. Returns an empty list when neither variable is set. */
export function loadHttpIdentities(
  env: NodeJS.ProcessEnv = process.env,
  readFile: (path: string) => string = (p) => fs.readFileSync(p, "utf8"),
): HttpIdentity[] {
  const inline = env.AFFINE_MCP_IDENTITIES?.trim();
  const filePath = env.AFFINE_MCP_IDENTITIES_FILE?.trim();
  if (inline && filePath) {
    throw new Error(`Set only one of ${IDENTITIES_ENV} and ${IDENTITIES_FILE_ENV}.`);
  }
  if (inline) return parseHttpIdentities(inline, IDENTITIES_ENV);
  if (filePath) {
    let content: string;
    try {
      content = readFile(filePath);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`Cannot read ${IDENTITIES_FILE_ENV} (${filePath}): ${detail}`);
    }
    return parseHttpIdentities(content, IDENTITIES_FILE_ENV);
  }
  return [];
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/**
 * Find the identity whose token matches. Every identity is compared so the
 * response time does not reveal which position (if any) matched.
 */
export function matchHttpIdentity(
  token: string,
  identities: readonly HttpIdentity[],
): HttpIdentity | undefined {
  const provided = digest(token);
  let matched: HttpIdentity | undefined;
  for (const identity of identities) {
    if (timingSafeEqual(provided, digest(identity.token)) && !matched) {
      matched = identity;
    }
  }
  return matched;
}

/** Identity names only; safe for logs and diagnostics. */
export function describeHttpIdentities(identities: readonly HttpIdentity[]): string {
  return identities.map((identity) => identity.name).join(", ");
}
