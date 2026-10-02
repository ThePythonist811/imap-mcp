import { NextResponse } from "next/server";
import { z } from "zod";
import { isAllowedRedirectUri, registerClient } from "@/lib/auth/oauth";

export const dynamic = "force-dynamic";

const schema = z.object({
  redirect_uris: z.array(z.string().url()).min(1).max(5),
  client_name: z.string().max(100).optional(),
  token_endpoint_auth_method: z.enum(["none", "client_secret_basic", "client_secret_post"]).optional(),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
});

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "invalid_client_metadata", error_description: parsed.error.message },
      { status: 400 },
    );
  }
  const bad = parsed.data.redirect_uris.filter((u) => !isAllowedRedirectUri(u));
  if (bad.length) {
    return NextResponse.json(
      { error: "invalid_redirect_uri", error_description: `redirect_uri not allowed: ${bad.join(", ")}` },
      { status: 400 },
    );
  }
  const { client_id, client_secret } = await registerClient({
    redirectUris: parsed.data.redirect_uris,
    name: parsed.data.client_name,
    tokenEndpointAuthMethod: parsed.data.token_endpoint_auth_method ?? "none",
  });
  return NextResponse.json(
    {
      client_id,
      client_secret,
      redirect_uris: parsed.data.redirect_uris,
      client_name: parsed.data.client_name,
      token_endpoint_auth_method: parsed.data.token_endpoint_auth_method ?? "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    },
    { status: 201 },
  );
}
