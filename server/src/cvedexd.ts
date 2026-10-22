import { Hono } from "hono";
import { actor, cnaUser, fail, newToken, sha256, submitter } from "./auth";
import type { AppContext, AppEnv } from "./env";
import { app } from "./index";
import { upstream } from "./upstream";

export const cvedexd = new Hono<AppEnv>();

const now = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')";

cvedexd.get("/review", async (c) => {
  cnaUser(c);
  const { results } = await c.env.DB.prepare(
    `SELECT cves.cve_id, submitters.name AS submitter, cves.record, cves.updated_at FROM cves
     JOIN submitters ON submitters.id = cves.submitter_id
     WHERE cves.state = 'in_review' ORDER BY cves.updated_at`,
  ).all<{ cve_id: string; submitter: string; record: string; updated_at: string }>();
  return c.json({ cves: results.map((row) => ({ ...row, record: JSON.parse(row.record) })) });
});

cvedexd.post("/cve/:id/approve", async (c) => {
  const headers = cnaUser(c);
  const id = c.req.param("id");
  const row = await inReview(c, id);
  const method = row.published_at ? "PUT" : "POST";
  const res = await upstream(c, headers, method, `/api/cve/${id}/cna`, row.record);
  if (res.ok) {
    await c.env.DB.prepare(
      `UPDATE cves SET state = 'published', published_at = ${now}, updated_at = ${now}
       WHERE cve_id = ?`,
    )
      .bind(id)
      .run();
  }
  return res;
});

cvedexd.post("/cve/:id/request-changes", async (c) => {
  cnaUser(c);
  const id = c.req.param("id");
  const { note } = await json<{ note?: unknown }>(c);
  if (typeof note !== "string" || !note) {
    throw fail(400, "BAD_INPUT", "`note` is required");
  }
  await inReview(c, id);
  await c.env.DB.prepare(
    `UPDATE cves SET state = 'reserved', note = ?, updated_at = ${now} WHERE cve_id = ?`,
  )
    .bind(note, id)
    .run();
  return c.json({ cve_id: id, state: "reserved", note });
});

cvedexd.get("/proposals", async (c) => {
  const s = submitter(c);
  const { results } = await c.env.DB.prepare(
    `SELECT id, method, path, body, created_at FROM proposals
     WHERE submitter_id = ? AND status = 'pending' ORDER BY created_at`,
  )
    .bind(s.submitterId)
    .all();
  return c.json({ proposals: results });
});

cvedexd.post("/proposals/:id/:decision{approve|deny}", async (c) => {
  const s = submitter(c);
  const id = c.req.param("id");
  const status = c.req.param("decision") === "approve" ? "approved" : "denied";
  const proposal = await c.env.DB.prepare(
    `UPDATE proposals SET status = ?, decided_at = ${now}
     WHERE id = ? AND submitter_id = ? AND status = 'pending' RETURNING method, path, body`,
  )
    .bind(status, id, s.submitterId)
    .first<{ method: string; path: string; body: string | null }>();
  if (!proposal) {
    throw fail(404, "PROPOSAL_NOT_FOUND", `No pending proposal ${id}`);
  }
  c.set("proposalId", id);
  if (status === "denied") {
    return c.json({ id, status });
  }
  const request = new Request(new URL(proposal.path, c.req.url), {
    method: proposal.method,
    headers: proposal.body ? { "content-type": "application/json" } : {},
    body: proposal.body,
  });
  return app.fetch(request, { ...c.env, REPLAY: { actor: s, proposalId: id } }, c.executionCtx);
});

cvedexd.get("/audit", async (c) => {
  cnaUser(c);
  const { user, since } = c.req.query();
  // ponytail: fixed 1000-row cap, add cursor pagination when audits outgrow it
  const { results } = await c.env.DB.prepare(
    `SELECT * FROM audit WHERE (?1 IS NULL OR actor = ?1) AND (?2 IS NULL OR ts >= ?2)
     ORDER BY id DESC LIMIT 1000`,
  )
    .bind(user ?? null, since ?? null)
    .all();
  return c.json({ audit: results });
});

cvedexd.post("/submitters", async (c) => {
  cnaUser(c);
  const { name } = await json<{ name?: unknown }>(c);
  if (typeof name !== "string" || !/^[\w.@-]{1,128}$/.test(name)) {
    throw fail(400, "BAD_INPUT", "`name` must be 1-128 letters, digits or `_.@-`");
  }
  const created = await c.env.DB.prepare(
    "INSERT INTO submitters (name) VALUES (?) ON CONFLICT DO NOTHING RETURNING id",
  )
    .bind(name)
    .first<{ id: number }>();
  if (!created) {
    throw fail(409, "SUBMITTER_EXISTS", `Submitter ${name} already exists`);
  }
  const token = await createToken(c, created.id, "user");
  return c.json({ id: created.id, name, ...token }, 201);
});

cvedexd.post("/submitters/:id{[0-9]+}/tokens", async (c) => {
  const id = Number(c.req.param("id"));
  const a = actor(c);
  if (a.kind !== "cna_user" && !(a.kind === "submitter" && a.submitterId === id)) {
    throw fail(403, "NOT_ALLOWED", "Only CNA users or the submitter can create tokens");
  }
  const { kind } = await json<{ kind?: unknown }>(c);
  if (kind !== "user" && kind !== "agent") {
    throw fail(400, "BAD_INPUT", "`kind` must be `user` or `agent`");
  }
  const exists = await c.env.DB.prepare("SELECT 1 FROM submitters WHERE id = ?").bind(id).first();
  if (!exists) {
    throw fail(404, "SUBMITTER_NOT_FOUND", `No submitter ${id}`);
  }
  return c.json(await createToken(c, id, kind), 201);
});

cvedexd.all("/*", () => {
  throw fail(404, "NOT_FOUND", "Unknown cvedexd endpoint");
});

async function createToken(c: AppContext, submitterId: number, kind: "user" | "agent") {
  const token = newToken();
  await c.env.DB.prepare("INSERT INTO tokens (submitter_id, kind, token_sha256) VALUES (?, ?, ?)")
    .bind(submitterId, kind, await sha256(token))
    .run();
  return { kind, token };
}

async function inReview(c: AppContext, id: string) {
  const row = await c.env.DB.prepare(
    "SELECT record, published_at FROM cves WHERE cve_id = ? AND state = 'in_review'",
  )
    .bind(id)
    .first<{ record: string; published_at: string | null }>();
  if (!row) {
    throw fail(404, "CVEID_NOT_FOUND", `${id} is not in review`);
  }
  return row;
}

async function json<T>(c: AppContext): Promise<T> {
  try {
    return await c.req.json<T>();
  } catch {
    throw fail(400, "BAD_INPUT", "Request body is not valid JSON");
  }
}
