import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { db } from "@/lib/db";
import {
  oauthAuthCodes,
  oauthClients,
  oauthTokens,
  type OAuthToken,
} from "@/lib/db/schema";

const AUTH_CODE_TTL_SECONDS = 10 * 60;

function accessTokenTtl(): number {
  return Number(process.env.OAUTH_ACCESS_TOKEN_TTL ?? 3600);
}
function refreshTokenTtl(): number {
  return Number(process.env.OAUTH_REFRESH_TOKEN_TTL ?? 60 * 60 * 24 * 30);
}

export function appBaseUrl(): string {
  const v = process.env.NEXT_PUBLIC_APP_URL;
  if (!v) throw new Error("NEXT_PUBLIC_APP_URL is required");
  return v.replace(/\/$/, "");
}

export function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function verifyPkce(
  verifier: string,
  challenge: string,
  method: string,
): boolean {
  if (method !== "S256") return false;
  const digest = createHash("sha256").update(verifier).digest();
  return digest.toString("base64url") === challenge;
}

export async function registerClient(input: {
  redirectUris: string[];
  name?: string;
  tokenEndpointAuthMethod?: string;
}): Promise<{ client_id: string; client_secret?: string }> {
  const clientId = `mcp_${randomToken(12)}`;
  const authMethod = input.tokenEndpointAuthMethod ?? "none";
  let clientSecret: string | undefined;
  let clientSecretHash: string | null = null;
  if (authMethod !== "none") {
    clientSecret = randomToken(32);
    clientSecretHash = sha256(clientSecret);
  }
  await db.insert(oauthClients).values({
    id: clientId,
    clientSecretHash,
    redirectUris: input.redirectUris,
    name: input.name ?? null,
    tokenEndpointAuthMethod: authMethod,
  });
  return { client_id: clientId, client_secret: clientSecret };
}

export async function loadClient(clientId: string) {
  const [row] = await db
    .select()
    .from(oauthClients)
    .where(eq(oauthClients.id, clientId))
    .limit(1);
  return row ?? null;
}

export async function createAuthCode(input: {
  clientId: string;
  userId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope: string | null;
}): Promise<string> {
  const code = randomToken(32);
  // Only the hash is stored, like access/refresh tokens.
  await db.insert(oauthAuthCodes).values({
    code: sha256(code),
    clientId: input.clientId,
    userId: input.userId,
    redirectUri: input.redirectUri,
    codeChallenge: input.codeChallenge,
    codeChallengeMethod: input.codeChallengeMethod,
    scope: input.scope,
    expiresAt: new Date(Date.now() + AUTH_CODE_TTL_SECONDS * 1000),
  });
  return code;
}

export async function consumeAuthCode(
  code: string,
): Promise<{
  clientId: string;
  userId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope: string | null;
} | null> {
  // Single UPDATE ... RETURNING: two concurrent redemptions cannot both succeed.
  const [row] = await db
    .update(oauthAuthCodes)
    .set({ consumedAt: new Date() })
    .where(
      and(
        eq(oauthAuthCodes.code, sha256(code)),
        isNull(oauthAuthCodes.consumedAt),
        gt(oauthAuthCodes.expiresAt, new Date()),
      ),
    )
    .returning();
  if (!row) return null;
  return {
    clientId: row.clientId,
    userId: row.userId,
    redirectUri: row.redirectUri,
    codeChallenge: row.codeChallenge,
    codeChallengeMethod: row.codeChallengeMethod,
    scope: row.scope,
  };
}

export async function issueTokenPair(input: {
  clientId: string;
  userId: string;
  scope: string | null;
}): Promise<{
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: "Bearer";
  scope: string | null;
}> {
  const access = randomToken(32);
  const refresh = randomToken(32);
  const accessTtl = accessTokenTtl();
  const refreshTtl = refreshTokenTtl();
  await db.insert(oauthTokens).values({
    accessTokenHash: sha256(access),
    refreshTokenHash: sha256(refresh),
    clientId: input.clientId,
    userId: input.userId,
    scope: input.scope,
    accessExpiresAt: new Date(Date.now() + accessTtl * 1000),
    refreshExpiresAt: new Date(Date.now() + refreshTtl * 1000),
  });
  return {
    access_token: access,
    refresh_token: refresh,
    expires_in: accessTtl,
    token_type: "Bearer",
    scope: input.scope,
  };
}

export async function resolveAccessToken(access: string): Promise<OAuthToken | null> {
  const hash = sha256(access);
  const [row] = await db
    .select()
    .from(oauthTokens)
    .where(
      and(
        eq(oauthTokens.accessTokenHash, hash),
        gt(oauthTokens.accessExpiresAt, new Date()),
        isNull(oauthTokens.revokedAt),
      ),
    )
    .limit(1);
  return row ?? null;
}

export async function rotateRefresh(refresh: string): Promise<OAuthToken | null> {
  // Revoke-and-return in one statement so a refresh token can be used only once.
  const [row] = await db
    .update(oauthTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(oauthTokens.refreshTokenHash, sha256(refresh)),
        isNull(oauthTokens.revokedAt),
        gt(oauthTokens.refreshExpiresAt, new Date()),
      ),
    )
    .returning();
  return row ?? null;
}

export async function revokeByAccessToken(access: string): Promise<void> {
  const hash = sha256(access);
  await db
    .update(oauthTokens)
    .set({ revokedAt: new Date() })
    .where(eq(oauthTokens.accessTokenHash, hash));
}

export async function revokeByRefreshToken(refresh: string): Promise<void> {
  const hash = sha256(refresh);
  await db
    .update(oauthTokens)
    .set({ revokedAt: new Date() })
    .where(eq(oauthTokens.refreshTokenHash, hash));
}

// --- Redirect allowlist ---------------------------------------------------------
// Dynamic client registration is anonymous. Without this, anyone could register a
// client that redirects to their own server and phish an authorization code.

const DEFAULT_REDIRECTS = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
];

export function isAllowedRedirectUri(uri: string): boolean {
  const exact = (process.env.ALLOWED_REDIRECT_URIS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if ((exact.length ? exact : DEFAULT_REDIRECTS).includes(uri)) return true;
  if (process.env.ALLOW_LOOPBACK_REDIRECTS === "false") return false;
  try {
    const u = new URL(uri);
    return u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1");
  } catch {
    return false;
  }
}

// --- Consent CSRF token -----------------------------------------------------------
// The consent form carries an HMAC over (user, client, redirect, PKCE challenge, expiry),
// so a cross-site POST cannot approve a request and a token cannot be replayed elsewhere.

function consentKey(): Buffer {
  const raw = process.env.MCP_MASTER_KEY;
  if (!raw) throw new Error("MCP_MASTER_KEY is not set");
  return createHmac("sha256", Buffer.from(raw, "base64")).update("oauth-consent-v1").digest();
}

interface ConsentFields {
  userId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
}

function consentMac(p: ConsentFields, exp: number): string {
  return createHmac("sha256", consentKey())
    .update([p.userId, p.clientId, p.redirectUri, p.codeChallenge, exp].join("\n"))
    .digest("base64url");
}

export function signConsent(p: ConsentFields): string {
  const exp = Math.floor(Date.now() / 1000) + 600;
  return `${exp}.${consentMac(p, exp)}`;
}

export function verifyConsent(token: string, p: ConsentFields): boolean {
  const [expStr, mac] = token.split(".");
  const exp = Number(expStr);
  if (!exp || !mac || exp < Math.floor(Date.now() / 1000)) return false;
  const a = Buffer.from(mac);
  const b = Buffer.from(consentMac(p, exp));
  return a.length === b.length && timingSafeEqual(a, b);
}
