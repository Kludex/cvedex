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
    throw fail(401, "UNAUTHORIZED", "CVE-API-USER and CVE-API-KEY headers are required");
  }
  const token = await c.env.DB.prepare(
    `SELECT tokens.id, tokens.kind, submitters.id AS submitter_id FROM tokens
     JOIN submitters ON submitters.id = tokens.submitter_id
     WHERE submitters.name = ? AND tokens.token_sha256 = ?`,
  )
    .bind(headers["CVE-API-USER"], await sha256(headers["CVE-API-KEY"]))
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
    throw fail(401, "UNAUTHORIZED", "CVE-API-ORG header is required");
  }
  const org = encodeURIComponent(headers["CVE-API-ORG"]);
  const user = encodeURIComponent(headers["CVE-API-USER"]);
  const check = await upstream(c, headers, "GET", `/api/org/${org}/user/${user}`);
  if (!check.ok) {
    throw new HTTPException(check.status as 401, { res: check });
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

export function fail(status: 400 | 401 | 403 | 404 | 409, error: string, message: string) {
  return new HTTPException(status, { res: Response.json({ error, message }, { status }) });
}

export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function newToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `cvedexd_${btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, "")}`;
}
