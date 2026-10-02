import { isAllowedRedirectUri, loadClient } from "@/lib/auth/oauth";

export interface AuthorizeParams {
  clientId: string;
  clientName: string | null;
  redirectUri: string;
  codeChallenge: string;
  state: string;
  scope: string | null;
}

/** Validates an authorization request; shared by the GET redirect, the consent page and the POST. */
export async function validateAuthorizeParams(
  get: (k: string) => string | null,
): Promise<{ ok: true; params: AuthorizeParams } | { ok: false; error: string }> {
  const clientId = get("client_id");
  const redirectUri = get("redirect_uri");
  const codeChallenge = get("code_challenge");
  if (!clientId || !redirectUri || !codeChallenge || get("response_type") !== "code") {
    return { ok: false, error: "missing required params" };
  }
  if ((get("code_challenge_method") ?? "S256") !== "S256") return { ok: false, error: "only S256 supported" };
  const client = await loadClient(clientId);
  if (!client) return { ok: false, error: "unknown client" };
  // Also checked here so clients registered before the allowlist existed are covered.
  if (!client.redirectUris.includes(redirectUri) || !isAllowedRedirectUri(redirectUri)) {
    return { ok: false, error: "redirect_uri not allowed" };
  }
  return {
    ok: true,
    params: {
      clientId,
      clientName: client.name,
      redirectUri,
      codeChallenge,
      state: get("state") ?? "",
      scope: get("scope"),
    },
  };
}
