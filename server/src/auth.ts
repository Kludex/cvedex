import { HTTPException } from "hono/http-exception";
import { createMiddleware } from "hono/factory";
import type { Actor, AppContext, AppEnv, CveHeaders, Submitter } from "./env";
import { upstream } from "./upstream";

export const authenticate = createMiddleware<AppEnv>(async (c, next) => {
  if (c.env.REPLAY) {
    c.set("actor", c.env.REPLAY.actor);
    c.set("proposalId", c.env.REPLAY.proposalId);
    return next();
  }
  const headers = {
    "CVE-API-ORG": c.req.header("CVE-API-ORG") ?? "",
    "CVE-API-USER": c.req.header("CVE-API-USER") ?? "",
    "CVE-API-KEY": c.req.header("CVE-API-KEY") ?? "",
  };
  if (!headers["CVE-API-USER"] || !headers["CVE-API-KEY"]) {
    throw refuse(c, fail(401, "UNAUTHORIZED", "CVE-API-USER and CVE-API-KEY headers are required"));
  }
  const token = await c.env.DB.prepare(
    `UPDATE tokens SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
     WHERE token_sha256 = ? AND revoked_at IS NULL
     AND submitter_id = (SELECT id FROM submitters WHERE name = ? AND disabled_at IS NULL)
     RETURNING id, kind, submitter_id`,
  )
    .bind(await sha256(headers["CVE-API-KEY"]), headers["CVE-API-USER"])
    .first<{ id: number; kind: "user" | "agent"; submitter_id: number }>();
  if (token) {
    const kind = token.kind === "agent" ? "agent" : "submitter";
    c.set("actor", {
      kind,
      name: headers["CVE-API-USER"],
      submitterId: token.submitter_id,
      tokenId: token.id,
    });
    return next();
  }
  if (!headers["CVE-API-ORG"]) {
    throw refuse(c, fail(401, "UNAUTHORIZED", "CVE-API-ORG header is required"));
  }
  if (headers["CVE-API-ORG"] !== c.env.CVE_API_ORG) {
    throw refuse(c, fail(403, "NOT_ALLOWED", `This cvedexd serves ${c.env.CVE_API_ORG} only`));
  }
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
  if (!(await c.env.AUTH_LIMITER.limit({ key: ip })).success) {
    throw refuse(c, fail(429, "RATE_LIMITED", "Too many sign-ins, try again in a minute"));
  }
  const org = encodeURIComponent(headers["CVE-API-ORG"]);
  const user = encodeURIComponent(headers["CVE-API-USER"]);
  const check = await upstream(c, headers, "GET", `/api/org/${org}/user/${user}`);
  if (!check.ok) {
    throw refuse(c, new HTTPException(check.status as 401, { res: check }));
  }
  c.set("actor", { kind: "cna_user", name: headers["CVE-API-USER"], headers });
  return next();
});

export function actor(c: AppContext): Actor {
  return c.get("actor")!;
}

export function cnaUser(c: AppContext): CveHeaders {
  const a = actor(c);
  if (a.kind !== "cna_user") {
    throw fail(403, "NOT_ALLOWED", "Only CNA users can do this");
  }
  return a.headers;
}

export function submitter(c: AppContext): Submitter {
  const a = actor(c);
  if (a.kind !== "submitter") {
    throw fail(403, "NOT_ALLOWED", "Only submitters can do this");
  }
  return a;
}

export function fail(
  status: 400 | 401 | 403 | 404 | 409 | 413 | 429,
  error: string,
  message: string,
) {
  return new HTTPException(status, { res: Response.json({ error, message }, { status }) });
}

/** Logs a refused sign-in to Workers Logs. The audit table holds authenticated requests only. */
function refuse(c: AppContext, err: HTTPException): HTTPException {
  const url = new URL(c.req.url);
  console.warn(
    JSON.stringify({
      event: "sign_in_refused",
      status: err.status,
      user: c.req.header("CVE-API-USER") ?? null,
      org: c.req.header("CVE-API-ORG") ?? null,
      ip: c.req.header("CF-Connecting-IP") ?? null,
      method: c.req.method,
      path: url.pathname + url.search,
    }),
  );
  return err;
}

export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function newToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `cvedexd_${btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, "")}`;
}
