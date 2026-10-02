import { getCurrentUserRowId } from "@/lib/auth/clerk";
import { validateAuthorizeParams } from "@/lib/auth/authorize";
import { signConsent } from "@/lib/auth/oauth";

export const dynamic = "force-dynamic";

export default async function ConsentPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const get = (k: string) => (typeof sp[k] === "string" ? (sp[k] as string) : null);
  const v = await validateAuthorizeParams(get);
  if (!v.ok) {
    return (
      <div className="container-narrow">
        <div className="alert alert-error">Invalid authorization request: {v.error}</div>
      </div>
    );
  }
  const p = v.params;
  const userId = await getCurrentUserRowId();
  const consentToken = signConsent({
    userId,
    clientId: p.clientId,
    redirectUri: p.redirectUri,
    codeChallenge: p.codeChallenge,
  });

  return (
    <div className="container-narrow">
      <div className="card stack">
        <h2>Allow access to your email?</h2>
        <p>
          <strong>{p.clientName ?? "Unnamed client"}</strong> wants to read, send and manage email and calendar
          events in all accounts you configured here.
        </p>
        <p className="muted" style={{ fontSize: 13 }}>
          Redirects to: <code>{new URL(p.redirectUri).origin}</code>
          <br />
          Client ID: <code>{p.clientId}</code>
        </p>
        <div className="alert alert-warning" style={{ fontSize: 13 }}>
          Only allow this if you just started connecting this client yourself.
        </div>
        <form method="post" action="/api/oauth/authorize" className="row">
          {[
            ["client_id", p.clientId],
            ["redirect_uri", p.redirectUri],
            ["code_challenge", p.codeChallenge],
            ["code_challenge_method", "S256"],
            ["response_type", "code"],
            ["state", p.state],
            ["scope", p.scope ?? ""],
            ["consent_token", consentToken],
          ].map(([name, value]) => (
            <input key={name} type="hidden" name={name} value={value} />
          ))}
          <button className="btn btn-primary" name="decision" value="allow">Allow</button>
          <button className="btn" name="decision" value="deny">Deny</button>
        </form>
      </div>
    </div>
  );
}
