import { Hono } from "hono";
import { actor, fail } from "./auth";
import type { AppContext, AppEnv } from "./env";
import { forward, serviceHeaders, upstream } from "./upstream";

export const cve = new Hono<AppEnv>();

type CveRow = {
  cve_id: string;
  submitter_id: number;
  state: "reserved" | "in_review" | "published";
  record: string | null;
  note: string | null;
  reserved_at: string;
  updated_at: string;
};

cve.post("/cve-id", async (c) => {
  const a = actor(c);
  if (a.kind === "cna_user") {
    return forward(c, a.headers);
  }
  const query = new URLSearchParams(new URL(c.req.url).search);
  query.set("short_name", c.env.CVE_API_ORG);
  const res = await upstream(c, serviceHeaders(c), "POST", `/api/cve-id?${query}`);
  if (res.ok) {
    const { cve_ids } = await res.clone().json<{ cve_ids: { cve_id: string }[] }>();
    await c.env.DB.batch(
      cve_ids.map(({ cve_id }) =>
        c.env.DB.prepare(
          "INSERT INTO cves (cve_id, submitter_id, state) VALUES (?, ?, 'reserved')",
        ).bind(cve_id, a.submitterId),
      ),
    );
  }
  return res;
});

cve.get("/cve-id", async (c) => {
  const a = actor(c);
  if (a.kind === "cna_user") {
    return forward(c, a.headers);
  }
  const { results } = await c.env.DB.prepare(
    "SELECT * FROM cves WHERE submitter_id = ? ORDER BY cve_id",
  )
    .bind(a.submitterId)
    .all<CveRow>();
  return c.json({
    totalCount: results.length,
    itemsPerPage: results.length,
    pageCount: 1,
    currentPage: 1,
    cve_ids: results.map((row) => cveId(c, row, a.name)),
  });
});

cve.get("/cve-id/:id", async (c) => {
  const a = actor(c);
  if (a.kind === "cna_user") {
    return forward(c, a.headers);
  }
  return c.json(cveId(c, await owned(c, c.req.param("id"), a.submitterId), a.name));
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

cve.on(["POST", "PUT"], "/cve/:id/cna", async (c) => {
  const a = actor(c);
  if (a.kind === "cna_user") {
    return forward(c, a.headers);
  }
  const id = c.req.param("id");
  await owned(c, id, a.submitterId);
  const body = await c.req.text();
  try {
    JSON.parse(body);
  } catch {
    throw fail(400, "BAD_INPUT", "Request body is not valid JSON");
  }
  await c.env.DB.prepare(
    `UPDATE cves SET record = ?, state = 'in_review', note = NULL,
     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE cve_id = ? AND submitter_id = ?`,
  )
    .bind(body, id, a.submitterId)
    .run();
  return c.json({ message: `${id} was submitted for review`, state: "in_review" });
});

cve.all("/*", async (c) => {
  const a = actor(c);
  if (a.kind !== "cna_user") {
    throw fail(403, "NOT_ALLOWED", "Submitters can only reserve IDs and submit records");
  }
  return forward(c, a.headers);
});

async function owned(c: AppContext, id: string, submitterId: number): Promise<CveRow> {
  const row = await c.env.DB.prepare("SELECT * FROM cves WHERE cve_id = ? AND submitter_id = ?")
    .bind(id, submitterId)
    .first<CveRow>();
  if (!row) {
    throw fail(404, "CVEID_NOT_FOUND", `${id} is not one of your CVE IDs`);
  }
  return row;
}

function cveId(c: AppContext, row: CveRow, user: string) {
  const org = c.env.CVE_API_ORG;
  return {
    cve_id: row.cve_id,
    cve_year: row.cve_id.slice(4, 8),
    owning_cna: org,
    state: row.state === "published" ? "PUBLISHED" : "RESERVED",
    requested_by: { cna: org, user },
    reserved: row.reserved_at,
    time: { created: row.reserved_at, modified: row.updated_at },
    cvedexd: { state: row.state, note: row.note },
  };
}
