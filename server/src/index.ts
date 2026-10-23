import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { createMiddleware } from "hono/factory";
import { actor, authenticate, fail, sha256 } from "./auth";
import { cve } from "./cve";
import { cvedexd } from "./cvedexd";
import type { AppEnv } from "./env";
import { notify, serviceHeaders, upstream } from "./upstream";

const MAX_BODY = 1024 * 1024;
const MAX_PENDING_PROPOSALS = 50;
const PUBLISHED_MAX_AGE = 600;

const audit = createMiddleware<AppEnv>(async (c, next) => {
  const a = actor(c);
  const body = await c.req.text();
  const url = new URL(c.req.url);
  const row = await c.env.DB.prepare(
    `INSERT INTO audit (actor, actor_kind, token_id, method, path, body_sha256)
     VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
  )
    .bind(
      a.name,
      a.kind,
      a.kind === "cna_user" ? null : a.tokenId,
      c.req.method,
      url.pathname + url.search,
      body ? await sha256(body) : null,
    )
    .first<{ id: number }>();
  await next();
  await c.env.DB.prepare("UPDATE audit SET status = ?, proposal_id = ? WHERE id = ?")
    .bind(c.res.status, c.get("proposalId") ?? null, row!.id)
    .run();
});

const propose = createMiddleware<AppEnv>(async (c, next) => {
  const a = actor(c);
  if (a.kind !== "agent" || c.req.method === "GET" || c.req.method === "HEAD") {
    return next();
  }
  const pending = await c.env.DB.prepare(
    "SELECT count(*) AS n FROM proposals WHERE submitter_id = ? AND status = 'pending'",
  )
    .bind(a.submitterId)
    .first<{ n: number }>();
  if (pending!.n >= MAX_PENDING_PROPOSALS) {
    throw fail(429, "TOO_MANY_PROPOSALS", `${a.name} has ${pending!.n} proposals to decide first`);
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
  await notify(c, `An agent of ${a.name} proposed ${c.req.method} ${url.pathname}`);
  return c.json({ status: "pending_approval", proposal_id: id }, 202);
});

const limit = bodyLimit({
  maxSize: MAX_BODY,
  onError: () => {
    throw fail(413, "BAD_INPUT", "Request body is larger than 1 MiB");
  },
});

export const app = new Hono<AppEnv>();

app.get("/api/health-check", (c) => c.json({ server: "cvedexd", version: c.env.VERSION }));

// Public, so a website can list the CNA's CVEs. Cached, so visitors cannot make it call MITRE often.
app.get("/api/cvedexd/published", async (c) => {
  const key = new Request(new URL("/api/cvedexd/published", c.req.url));
  const cached = await caches.default.match(key);
  if (cached) {
    return cached;
  }
  const ids: string[] = [];
  let query = "state=PUBLISHED";
  for (;;) {
    const res = await upstream(c, serviceHeaders(c), "GET", `/api/cve-id?${query}`);
    if (!res.ok) {
      throw fail(502, "UPSTREAM_ERROR", `CVE Services answered ${res.status}`);
    }
    const page = await res.json<{
      cve_ids: { cve_id: string; state: string }[];
      nextPage?: number | null;
    }>();
    ids.push(...page.cve_ids.filter((id) => id.state === "PUBLISHED").map((id) => id.cve_id));
    if (!page.nextPage) {
      break;
    }
    query = `state=PUBLISHED&page=${page.nextPage}`;
  }
  const res = Response.json(ids, {
    headers: { "cache-control": `public, max-age=${PUBLISHED_MAX_AGE}` },
  });
  await caches.default.put(key, res.clone());
  return res;
});
app.use("/api/*", limit, authenticate, audit, propose);
app.route("/api/cvedexd", cvedexd);
app.route("/api", cve);

export default app;
