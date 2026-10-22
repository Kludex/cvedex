import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { actor, authenticate, sha256 } from "./auth";
import { cve } from "./cve";
import { cvedexd } from "./cvedexd";
import type { AppEnv } from "./env";

const audit = createMiddleware<AppEnv>(async (c, next) => {
  const body = await c.req.text();
  await next();
  const a = c.get("actor");
  const url = new URL(c.req.url);
  await c.env.DB.prepare(
    `INSERT INTO audit (actor, actor_kind, token_id, method, path, status, body_sha256, proposal_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      a?.name ?? c.req.header("CVE-API-USER") ?? null,
      a?.kind ?? null,
      a && a.kind !== "cna_user" ? a.tokenId : null,
      c.req.method,
      url.pathname + url.search,
      c.res.status,
      body ? await sha256(body) : null,
      c.get("proposalId") ?? null,
    )
    .run();
});

const propose = createMiddleware<AppEnv>(async (c, next) => {
  const a = actor(c);
  if (a.kind !== "agent" || c.req.method === "GET" || c.req.method === "HEAD") {
    return next();
  }
  const id = crypto.randomUUID();
  const url = new URL(c.req.url);
  const body = await c.req.text();
  await c.env.DB.prepare(
    "INSERT INTO proposals (id, submitter_id, token_id, method, path, body) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(id, a.submitterId, a.tokenId, c.req.method, url.pathname + url.search, body || null)
    .run();
  c.set("proposalId", id);
  return c.json({ status: "pending_approval", proposal_id: id }, 202);
});

export const app = new Hono<AppEnv>();

app.get("/api/health-check", (c) => c.json({ server: "cvedexd", version: c.env.VERSION }));
app.use("/api/*", audit, authenticate, propose);
app.route("/api/cvedexd", cvedexd);
app.route("/api", cve);

export default app;
