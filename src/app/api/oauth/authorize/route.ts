import { NextResponse } from "next/server";
import { getCurrentUserRowId } from "@/lib/auth/clerk";
import { validateAuthorizeParams } from "@/lib/auth/authorize";
import { appBaseUrl, createAuthCode, verifyConsent } from "@/lib/auth/oauth";

export const dynamic = "force-dynamic";

// GET never issues a code: it validates and sends the user to the consent page.
export async function GET(req: Request) {
  const url = new URL(req.url);
  const v = await validateAuthorizeParams((k) => url.searchParams.get(k));
  if (!v.ok) {
    return NextResponse.json({ error: "invalid_request", error_description: v.error }, { status: 400 });
  }
  return NextResponse.redirect(`${appBaseUrl()}/consent?${url.searchParams.toString()}`, 303);
}

function isSameOrigin(req: Request): boolean {
  const origin = req.headers.get("origin");
  if (origin && origin !== "null") return origin === new URL(appBaseUrl()).origin;
  // Browsers may send `Origin: null`; Sec-Fetch-Site is set by the browser and cannot be forged by pages.
  return req.headers.get("sec-fetch-site") === "same-origin";
}

// POST comes only from the consent form.
export async function POST(req: Request) {
  if (!isSameOrigin(req)) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  const userId = await getCurrentUserRowId();

  const form = await req.formData();
  const get = (k: string) => {
    const v = form.get(k);
    return typeof v === "string" ? v : null;
  };
  const v = await validateAuthorizeParams(get);
  if (!v.ok) {
    return NextResponse.json({ error: "invalid_request", error_description: v.error }, { status: 400 });
  }
  const p = v.params;
  const consentOk = verifyConsent(get("consent_token") ?? "", {
    userId,
    clientId: p.clientId,
    redirectUri: p.redirectUri,
    codeChallenge: p.codeChallenge,
  });
  if (!consentOk) return NextResponse.json({ error: "consent expired, please retry" }, { status: 400 });

  const redirect = new URL(p.redirectUri);
  if (p.state) redirect.searchParams.set("state", p.state);
  if (get("decision") !== "allow") {
    redirect.searchParams.set("error", "access_denied");
    return NextResponse.redirect(redirect.toString(), 303);
  }

  const code = await createAuthCode({
    clientId: p.clientId,
    userId,
    redirectUri: p.redirectUri,
    codeChallenge: p.codeChallenge,
    codeChallengeMethod: "S256",
    scope: p.scope,
  });
  redirect.searchParams.set("code", code);
  return NextResponse.redirect(redirect.toString(), 303);
}
