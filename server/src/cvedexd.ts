import { Hono } from "hono";
import { actor, cnaUser, fail, newToken, sha256, submitter } from "./auth";
import type { AppContext, AppEnv } from "./env";
import { app } from "./index";
import { notify, upstream } from "./upstream";

export const cvedexd = new Hono<AppEnv>();

const now = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')";

type Review = {
  cve_id: string;
  submitter: string;
  action: "publish" | "reject";
  revision: number;
  record: string;
  previous: string | null;
  published: string | null;
  updated_at: string;
};

cvedexd.get("/review", async (c) => {
  cnaUser(c);
  const { results } = await c.env.DB.prepare(
    `SELECT cves.cve_id, submitters.name AS submitter, cves.action, cves.revision, cves.record,
     previous.record AS previous, published.record AS published, cves.updated_at FROM cves
     JOIN submitters ON submitters.id = cves.submitter_id
     LEFT JOIN revisions AS previous
       ON previous.cve_id = cves.cve_id AND previous.revision = cves.revision - 1
     LEFT JOIN revisions AS published
       ON published.cve_id = cves.cve_id AND published.revision = cves.published_revision
     WHERE cves.state = 'in_review' ORDER BY cves.updated_at`,
  ).all<Review>();
  return c.json({
    cves: results.map((row) => ({
      ...row,
      record: JSON.parse(row.record),
      previous: row.previous && JSON.parse(row.previous),
      published: row.published && JSON.parse(row.published),
    })),
  });
});

cvedexd.post("/cve/:id/approve", async (c) => {
  const headers = cnaUser(c);
  const id = c.req.param("id");
  const revision = await reviewed(c, id);
  const row = await c.env.DB.prepare(
    `UPDATE cves SET state = 'publishing', updated_at = ${now}
     WHERE cve_id = ? AND state = 'in_review' AND revision = ?
     RETURNING record, action, published_at`,
  )
    .bind(id, revision)
    .first<{ record: string; action: "publish" | "reject"; published_at: string | null }>();
  if (!row) {
    throw await notReviewable(c, id);
  }
  let res: Response | undefined;
  try {
    const method = row.published_at ? "PUT" : "POST";
    const path = `/api/cve/${encodeURIComponent(id)}/${row.action === "publish" ? "cna" : "reject"}`;
    res = await upstream(c, headers, method, path, row.record);
  } finally {
    const done = row.action === "publish" ? "published" : "rejected";
    await c.env.DB.prepare(
      `UPDATE cves SET state = ?2, updated_at = ${now},
       published_at = CASE WHEN ?3 THEN coalesce(published_at, ${now}) ELSE published_at END,
       published_revision = CASE WHEN ?3 THEN revision ELSE published_revision END
       WHERE cve_id = ?1 AND state = 'publishing'`,
    )
      .bind(id, res?.ok ? done : "in_review", Boolean(res?.ok) && row.action === "publish")
      .run();
  }
  if (res.ok) {
    await notify(c, `${actor(c).name} approved ${id} (${row.action}, revision ${revision})`);
  }
  return res;
});

cvedexd.post("/cve/:id/request-changes", async (c) => {
  cnaUser(c);
  const id = c.req.param("id");
  const { note, revision } = await json<{ note?: unknown; revision?: unknown }>(c);
  if (typeof note !== "string" || !note) {
    throw fail(400, "BAD_INPUT", "`note` is required");
  }
  if (!Number.isInteger(revision)) {
    throw fail(400, "BAD_INPUT", "`revision` is required: the revision you reviewed");
  }
  const changed = await c.env.DB.prepare(
    `UPDATE cves SET state = 'reserved', note = ?, updated_at = ${now}
     WHERE cve_id = ? AND state = 'in_review' AND revision = ? RETURNING cve_id`,
  )
    .bind(note, id, revision)
    .first();
  if (!changed) {
    throw await notReviewable(c, id);
  }
  await notify(c, `${actor(c).name} requested changes to ${id}: ${note}`);
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

const AUDIT_PAGE = 500;

cvedexd.get("/audit", async (c) => {
  cnaUser(c);
  const { user, since, before } = c.req.query();
  const { results } = await c.env.DB.prepare(
    `SELECT * FROM audit WHERE (?1 IS NULL OR actor = ?1) AND (?2 IS NULL OR ts >= ?2)
     AND (?3 IS NULL OR id < ?3) ORDER BY id DESC LIMIT ${AUDIT_PAGE}`,
  )
    .bind(user ?? null, since ?? null, before ? Number(before) : null)
    .all<{ id: number }>();
  const next = results.length === AUDIT_PAGE ? results.at(-1)!.id : null;
  return c.json({ audit: results, next });
});

cvedexd.get("/submitters", async (c) => {
  cnaUser(c);
  const { results } = await c.env.DB.prepare(
    `SELECT submitters.id, submitters.name, submitters.created_at, submitters.disabled_at,
     (SELECT count(*) FROM cves WHERE submitter_id = submitters.id
       AND state IN ('reserved', 'in_review', 'publishing')) AS open_ids,
     (SELECT count(*) FROM tokens WHERE submitter_id = submitters.id
       AND revoked_at IS NULL) AS tokens
     FROM submitters ORDER BY submitters.name`,
  ).all();
  return c.json({ submitters: results });
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

cvedexd.post("/submitters/:id{[0-9]+}/:change{disable|enable}", async (c) => {
  cnaUser(c);
  const id = Number(c.req.param("id"));
  const disable = c.req.param("change") === "disable";
  const updated = await c.env.DB.prepare(
    `UPDATE submitters SET disabled_at = ${disable ? now : "NULL"} WHERE id = ?
     RETURNING id, name, created_at, disabled_at`,
  )
    .bind(id)
    .first();
  if (!updated) {
    throw fail(404, "SUBMITTER_NOT_FOUND", `No submitter ${id}`);
  }
  if (disable) {
    await denyPending(c, "submitter_id = ?", id);
  }
  return c.json(updated);
});

cvedexd.get("/submitters/:id{[0-9]+}/tokens", async (c) => {
  const id = await ownSubmitter(c);
  const { results } = await c.env.DB.prepare(
    `SELECT id, kind, created_at, last_used_at, revoked_at FROM tokens
     WHERE submitter_id = ? ORDER BY id`,
  )
    .bind(id)
    .all();
  return c.json({ tokens: results });
});

cvedexd.post("/submitters/:id{[0-9]+}/tokens", async (c) => {
  const id = await ownSubmitter(c);
  const { kind } = await json<{ kind?: unknown }>(c);
  if (kind !== "user" && kind !== "agent") {
    throw fail(400, "BAD_INPUT", "`kind` must be `user` or `agent`");
  }
  return c.json(await createToken(c, id, kind), 201);
});

cvedexd.delete("/tokens/:id{[0-9]+}", async (c) => {
  const a = actor(c);
  const id = Number(c.req.param("id"));
  const revoked = await c.env.DB.prepare(
    `UPDATE tokens SET revoked_at = coalesce(revoked_at, ${now})
     WHERE id = ?1 AND (?2 IS NULL OR submitter_id = ?2)
     RETURNING id, kind, created_at, last_used_at, revoked_at`,
  )
    .bind(id, a.kind === "cna_user" ? null : a.submitterId)
    .first();
  if (!revoked) {
    throw fail(404, "TOKEN_NOT_FOUND", `No token ${id} you can revoke`);
  }
  await denyPending(c, "token_id = ?", id);
  return c.json(revoked);
});

cvedexd.all("/*", () => {
  throw fail(404, "NOT_FOUND", "Unknown cvedexd endpoint");
});

/** The submitter in the path, if the caller is a CNA user or that submitter's own user token. */
async function ownSubmitter(c: AppContext): Promise<number> {
  const id = Number(c.req.param("id"));
  const a = actor(c);
  if (a.kind !== "cna_user" && !(a.kind === "submitter" && a.submitterId === id)) {
    throw fail(403, "NOT_ALLOWED", "Only CNA users or the submitter can manage tokens");
  }
  const exists = await c.env.DB.prepare("SELECT 1 FROM submitters WHERE id = ?").bind(id).first();
  if (!exists) {
    throw fail(404, "SUBMITTER_NOT_FOUND", `No submitter ${id}`);
  }
  return id;
}

async function denyPending(c: AppContext, where: string, id: number): Promise<void> {
  await c.env.DB.prepare(
    `UPDATE proposals SET status = 'denied', decided_at = ${now}
     WHERE status = 'pending' AND ${where}`,
  )
    .bind(id)
    .run();
}

async function createToken(c: AppContext, submitterId: number, kind: "user" | "agent") {
  const token = newToken();
  const created = await c.env.DB.prepare(
    "INSERT INTO tokens (submitter_id, kind, token_sha256) VALUES (?, ?, ?) RETURNING id",
  )
    .bind(submitterId, kind, await sha256(token))
    .first<{ id: number }>();
  return { token_id: created!.id, kind, token };
}

/** The revision the reviewer read, from the request body. */
async function reviewed(c: AppContext, id: string): Promise<number> {
  const { revision } = await json<{ revision?: unknown }>(c);
  if (!Number.isInteger(revision)) {
    throw fail(400, "BAD_INPUT", `\`revision\` is required: the revision of ${id} you reviewed`);
  }
  return revision as number;
}

async function notReviewable(c: AppContext, id: string) {
  const row = await c.env.DB.prepare("SELECT state, revision FROM cves WHERE cve_id = ?")
    .bind(id)
    .first<{ state: string; revision: number }>();
  if (row?.state === "in_review") {
    return fail(
      409,
      "STALE_REVISION",
      `${id} changed while you reviewed it. Review revision ${row.revision}`,
    );
  }
  return fail(404, "CVEID_NOT_FOUND", `${id} is not in review`);
}

async function json<T>(c: AppContext): Promise<T> {
  try {
    return await c.req.json<T>();
  } catch {
    throw fail(400, "BAD_INPUT", "Request body is not valid JSON");
  }
}
