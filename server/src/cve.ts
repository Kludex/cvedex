import { Hono } from "hono";
import { actor, fail } from "./auth";
import type { AppContext, AppEnv } from "./env";
import { forward, notify, serviceHeaders, upstream } from "./upstream";

export const cve = new Hono<AppEnv>();

export type CveState = "reserved" | "in_review" | "publishing" | "published" | "rejected";

type CveRow = {
  cve_id: string;
  submitter_id: number;
  state: CveState;
  record: string | null;
  revision: number;
  note: string | null;
  reserved_at: string;
  updated_at: string;
};

const OPEN = "('reserved', 'in_review', 'publishing')";

cve.post("/cve-id", async (c) => {
  const a = actor(c);
  if (a.kind === "cna_user") {
    return forward(c, a.headers);
  }
  const query = new URLSearchParams(new URL(c.req.url).search);
  const amount = Number(query.get("amount"));
  if (!Number.isInteger(amount) || amount < 1) {
    throw fail(400, "BAD_INPUT", "`amount` must be a positive whole number");
  }
  const open = await c.env.DB.prepare(
    `SELECT count(*) AS n FROM cves WHERE submitter_id = ? AND state IN ${OPEN}`,
  )
    .bind(a.submitterId)
    .first<{ n: number }>();
  const max = Number(c.env.MAX_OPEN_IDS);
  if (open!.n + amount > max) {
    throw fail(
      403,
      "EXCEEDED_ID_QUOTA",
      `You hold ${open!.n} unpublished IDs and may hold ${max}. Publish or reject some first`,
    );
  }
  query.set("short_name", c.env.CVE_API_ORG);
  const res = await upstream(c, serviceHeaders(c), "POST", `/api/cve-id?${query}`);
  if (res.ok) {
    const { cve_ids } = await res.clone().json<{ cve_ids: { cve_id: string }[] }>();
    try {
      await c.env.DB.batch(
        cve_ids.map(({ cve_id }) =>
          c.env.DB.prepare(
            "INSERT INTO cves (cve_id, submitter_id, state) VALUES (?, ?, 'reserved')",
          ).bind(cve_id, a.submitterId),
        ),
      );
    } catch (err) {
      const ids = cve_ids.map(({ cve_id }) => cve_id);
      console.error(JSON.stringify({ event: "reservation_not_recorded", submitter: a.name, ids }));
      throw err;
    }
  }
  return res;
});

cve.get("/cve-id", async (c) => {
  const a = actor(c);
  if (a.kind === "cna_user") {
    return forward(c, a.headers);
  }
  const query = c.req.query();
  const { state, cve_id_year: year } = query;
  const within = (time: string, field: string) =>
    (!query[`${field}.gt`] || Date.parse(time) > Date.parse(query[`${field}.gt`]!)) &&
    (!query[`${field}.lt`] || Date.parse(time) < Date.parse(query[`${field}.lt`]!));
  const { results } = await c.env.DB.prepare(
    "SELECT * FROM cves WHERE submitter_id = ? ORDER BY cve_id",
  )
    .bind(a.submitterId)
    .all<CveRow>();
  const ids = results
    .map((row) => cveId(c, row, a.name))
    .filter(
      (id) =>
        (!state || id.state === state) &&
        (!year || id.cve_year === year) &&
        within(id.time.created, "time_reserved") &&
        within(id.time.modified, "time_modified"),
    );
  return c.json({
    totalCount: ids.length,
    itemsPerPage: ids.length,
    pageCount: 1,
    currentPage: 1,
    cve_ids: ids,
  });
});

cve.get("/cve-id/:id", async (c) => {
  const a = actor(c);
  if (a.kind === "cna_user") {
    return forward(c, a.headers);
  }
  return c.json(cveId(c, await owned(c, c.req.param("id"), a.submitterId), a.name));
});

cve.put("/cve-id/:id", async (c) => {
  const a = actor(c);
  if (a.kind !== "cna_user") {
    throw fail(403, "NOT_ALLOWED", "Submitters can only reserve IDs and submit records");
  }
  const res = await forward(c, a.headers);
  const states: Record<string, CveState> = { REJECTED: "rejected", RESERVED: "reserved" };
  const state = states[c.req.query("state") ?? ""];
  if (res.ok && state) {
    await sync(c, c.req.param("id"), state);
  }
  return res;
});

cve.get("/cve/:id", async (c) => {
  const a = actor(c);
  const row = await c.env.DB.prepare("SELECT * FROM cves WHERE cve_id = ? AND record IS NOT NULL")
    .bind(c.req.param("id"))
    .first<CveRow>();
  if (row && (a.kind === "cna_user" || row.submitter_id === a.submitterId)) {
    return c.json(JSON.parse(row.record!));
  }
  return forward(c, a.kind === "cna_user" ? a.headers : {});
});

cve.on(["POST", "PUT"], "/cve/:id/:action{cna|reject}", async (c) => {
  const a = actor(c);
  const id = c.req.param("id");
  const action = c.req.param("action") === "cna" ? "publish" : "reject";
  const body = await c.req.text();
  if (a.kind === "cna_user") {
    const res = await forward(c, a.headers);
    if (res.ok) {
      await sync(c, id, action === "publish" ? "published" : "rejected", body);
    }
    return res;
  }
  const row = await owned(c, id, a.submitterId);
  try {
    JSON.parse(body);
  } catch {
    throw fail(400, "BAD_INPUT", "Request body is not valid JSON");
  }
  const submitted = await c.env.DB.prepare(
    `UPDATE cves SET record = ?, action = ?, state = 'in_review', note = NULL,
     revision = revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
     WHERE cve_id = ? AND submitter_id = ? AND state IN ('reserved', 'in_review', 'published')
     RETURNING revision`,
  )
    .bind(body, action, id, a.submitterId)
    .first<{ revision: number }>();
  if (!submitted) {
    throw fail(409, "BAD_STATE", `${id} is ${row.state.replace("_", " ")} and cannot change now`);
  }
  await notify(c, `${a.name} sent ${id} for review (${action}, revision ${submitted.revision})`);
  return c.json({
    message: `${id} was submitted for review`,
    state: "in_review",
    revision: submitted.revision,
  });
});

cve.all("/*", async (c) => {
  const a = actor(c);
  if (a.kind !== "cna_user") {
    throw fail(403, "NOT_ALLOWED", "Submitters can only reserve IDs and submit records");
  }
  return forward(c, a.headers);
});

/** Records a CNA user's direct write to an ID that cvedexd tracks. */
async function sync(c: AppContext, id: string, state: CveState, body?: string): Promise<void> {
  const published =
    state === "published" ? "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')" : "published_at";
  const record = body
    ? `, record = ?2, action = ?3, revision = revision + 1, published_revision = revision + 1`
    : "";
  await c.env.DB.prepare(
    `UPDATE cves SET state = ?1, note = NULL, published_at = ${published},
     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')${record} WHERE cve_id = ?4`,
  )
    .bind(state, body ?? null, state === "rejected" ? "reject" : "publish", id)
    .run();
}

async function owned(c: AppContext, id: string, submitterId: number): Promise<CveRow> {
  const row = await c.env.DB.prepare("SELECT * FROM cves WHERE cve_id = ? AND submitter_id = ?")
    .bind(id, submitterId)
    .first<CveRow>();
  if (!row) {
    throw fail(404, "CVEID_NOT_FOUND", `${id} is not one of your CVE IDs`);
  }
  return row;
}

const UPSTREAM_STATE: Record<CveState, string> = {
  reserved: "RESERVED",
  in_review: "RESERVED",
  publishing: "RESERVED",
  published: "PUBLISHED",
  rejected: "REJECTED",
};

function cveId(c: AppContext, row: CveRow, user: string) {
  const org = c.env.CVE_API_ORG;
  return {
    cve_id: row.cve_id,
    cve_year: row.cve_id.slice(4, 8),
    owning_cna: org,
    state: UPSTREAM_STATE[row.state],
    requested_by: { cna: org, user },
    reserved: row.reserved_at,
    time: { created: row.reserved_at, modified: row.updated_at },
    cvedexd: { state: row.state, note: row.note, revision: row.revision },
  };
}
