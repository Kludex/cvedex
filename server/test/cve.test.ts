import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import published from "../../testdata/recorded/cve-2025-0001.json";
import recordDne from "../../testdata/recorded/cve-record-dne.json";
import {
  alice,
  aliceCheck,
  api,
  badRequest,
  cassette,
  createSubmitter,
  cveIdFor,
  cveIdList,
  mockUpstream,
  publish,
  record,
  reserveAs,
  reserved,
} from "./helpers";

describe("CNA users", () => {
  it("reserve with their own key", async () => {
    const calls = mockUpstream(aliceCheck, {
      method: "POST",
      path: "/api/cve-id?amount=1&cve_year=2026&short_name=acme",
      body: reserved(cveIdFor(1)),
    });
    const res = await api("/api/cve-id?amount=1&cve_year=2026&short_name=acme", {
      method: "POST",
      headers: alice,
    });
    expect(res.status).toBe(200);
    expect(calls[1]?.headers.get("CVE-API-KEY")).toBe("alice-key");
  });

  it("list and show IDs upstream", async () => {
    mockUpstream(
      aliceCheck,
      { method: "GET", path: "/api/cve-id?state=RESERVED", body: cveIdList },
      { method: "GET", path: "/api/cve-id/CVE-2026-0002", body: cveIdList.cve_ids[0] },
    );
    const list = await api("/api/cve-id?state=RESERVED", { headers: alice });
    expect(await list.json()).toEqual(cveIdList);
    const one = await api("/api/cve-id/CVE-2026-0002", { headers: alice });
    expect(await one.json()).toEqual(cveIdList.cve_ids[0]);
  });

  it("publish directly, with upstream errors returned verbatim", async () => {
    const calls = mockUpstream(
      aliceCheck,
      { method: "POST", path: "/api/cve/CVE-2026-0002/cna", body: publish },
      { method: "PUT", path: "/api/cve/CVE-2026-0002/cna", status: 400, body: badRequest },
    );
    const created = await api("/api/cve/CVE-2026-0002/cna", {
      method: "POST",
      headers: alice,
      body: record,
    });
    expect(await created.json()).toEqual(publish);
    expect(JSON.parse(calls[1]!.body)).toEqual(record);
    const updated = await api("/api/cve/CVE-2026-0002/cna", {
      method: "PUT",
      headers: alice,
      body: record,
    });
    expect(updated.status).toBe(400);
    expect(await updated.json()).toEqual(badRequest);
  });

  it("reach any other endpoint upstream", async () => {
    mockUpstream(aliceCheck, { method: "GET", path: "/api/org/acme/users", body: { users: [] } });
    const res = await api("/api/org/acme/users", { headers: alice });
    expect(await res.json()).toEqual({ users: [] });
  });

  it("read published records upstream", async () => {
    const record = cassette(published);
    mockUpstream(aliceCheck, record);
    const res = await api(record.path, { headers: alice });
    expect(await res.text()).toBe(record.body);
  });

  it("return upstream errors verbatim", async () => {
    const dne = cassette(recordDne);
    mockUpstream(aliceCheck, dne);
    const res = await api(dne.path, { headers: alice });
    expect(res.status).toBe(404);
    expect(res.headers.get("ratelimit-limit")).toBe(dne.headers!["ratelimit-limit"]);
    expect(await res.text()).toBe(dne.body);
  });
});

describe("submitters", () => {
  it("reserve through the service account and own the ID", async () => {
    const bob = await createSubmitter();
    const calls = mockUpstream({
      method: "POST",
      path: "/api/cve-id?amount=1&cve_year=2026&short_name=acme",
      body: reserved(cveIdFor(99001)),
    });
    const res = await api("/api/cve-id?amount=1&cve_year=2026&short_name=other", {
      method: "POST",
      headers: bob.headers,
    });
    expect(res.status).toBe(200);
    expect(calls[0]?.headers.get("CVE-API-USER")).toBe("service@acme.test");
    expect(calls[0]?.headers.get("CVE-API-KEY")).toBe("service-key");

    const list = await api("/api/cve-id", { headers: bob.headers });
    const body = await list.json<{ totalCount: number; cve_ids: Record<string, unknown>[] }>();
    expect(body.totalCount).toBe(1);
    expect(body.cve_ids[0]).toMatchObject({
      cve_id: cveIdFor(99001),
      cve_year: "2026",
      owning_cna: "acme",
      state: "RESERVED",
      requested_by: { cna: "acme", user: bob.headers["CVE-API-USER"] },
      cvedexd: { state: "reserved", note: null, revision: 0 },
    });
  });

  it("reserve a positive amount within their open ID limit", async () => {
    const bob = await createSubmitter();
    const calls = mockUpstream();
    const none = await api("/api/cve-id?amount=0", { method: "POST", headers: bob.headers });
    expect(none.status).toBe(400);
    const many = await api("/api/cve-id?amount=11", { method: "POST", headers: bob.headers });
    expect(many.status).toBe(403);
    expect(await many.json()).toEqual({
      error: "EXCEEDED_ID_QUOTA",
      message: "You hold 0 unpublished IDs and may hold 10. Publish or reject some first",
    });
    expect(calls).toEqual([]);
  });

  it("are told which reserved IDs could not be recorded", async () => {
    const bob = await createSubmitter();
    const carol = await createSubmitter();
    const id = await reserveAs(bob);
    mockUpstream({
      method: "POST",
      path: "/api/cve-id?amount=1&short_name=acme",
      body: reserved(id),
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await api("/api/cve-id?amount=1", { method: "POST", headers: carol.headers });
    expect(res.status).toBe(500);
    expect(JSON.parse(error.mock.calls[0]![0] as string)).toEqual({
      event: "reservation_not_recorded",
      submitter: carol.headers["CVE-API-USER"],
      ids: [id],
    });
  });

  it("filter their IDs by state and year", async () => {
    const bob = await createSubmitter();
    const id = await reserveAs(bob);
    const list = async (query: string) => {
      const res = await api(`/api/cve-id?${query}`, { headers: bob.headers });
      return (await res.json<{ cve_ids: { cve_id: string }[] }>()).cve_ids.map((c) => c.cve_id);
    };
    expect(await list("state=RESERVED&cve_id_year=2026")).toEqual([id]);
    expect(await list("state=PUBLISHED")).toEqual([]);
    expect(await list("cve_id_year=2025")).toEqual([]);
    expect(
      await list("time_reserved.gt=2000-01-01T00:00:00Z&time_modified.lt=2999-01-01T00:00:00Z"),
    ).toEqual([id]);
    expect(await list("time_reserved.lt=2000-01-01T00:00:00Z")).toEqual([]);
    expect(await list("time_modified.gt=2999-01-01T00:00:00Z")).toEqual([]);
  });

  it("get upstream reservation errors verbatim and own nothing", async () => {
    const bob = await createSubmitter();
    mockUpstream({
      method: "POST",
      path: "/api/cve-id?amount=1&short_name=acme",
      status: 400,
      body: badRequest,
    });
    const res = await api("/api/cve-id?amount=1", { method: "POST", headers: bob.headers });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(badRequest);
    const list = await api("/api/cve-id", { headers: bob.headers });
    expect((await list.json<{ totalCount: number }>()).totalCount).toBe(0);
  });

  it("see only their own IDs", async () => {
    const bob = await createSubmitter();
    const carol = await createSubmitter();
    const id = await reserveAs(bob);
    const own = await api(`/api/cve-id/${id}`, { headers: bob.headers });
    expect((await own.json<{ cve_id: string }>()).cve_id).toBe(id);
    const other = await api(`/api/cve-id/${id}`, { headers: carol.headers });
    expect(other.status).toBe(404);
  });

  it("submit a record for review instead of publishing", async () => {
    const bob = await createSubmitter();
    const id = await reserveAs(bob);
    const calls = mockUpstream();
    const res = await api(`/api/cve/${id}/cna`, {
      method: "POST",
      headers: bob.headers,
      body: record,
    });
    expect(await res.json()).toEqual({
      message: `${id} was submitted for review`,
      state: "in_review",
      revision: 1,
    });
    expect(calls).toEqual([]);

    const stored = await api(`/api/cve/${id}`, { headers: bob.headers });
    expect(await stored.json()).toEqual(record);
  });

  it("cannot submit invalid JSON or for IDs they do not own", async () => {
    const bob = await createSubmitter();
    const carol = await createSubmitter();
    const id = await reserveAs(bob);
    const invalid = await api(`/api/cve/${id}/cna`, {
      method: "PUT",
      headers: bob.headers,
      body: "{",
    });
    expect(invalid.status).toBe(400);
    const notOwned = await api(`/api/cve/${id}/cna`, {
      method: "POST",
      headers: carol.headers,
      body: record,
    });
    expect(notOwned.status).toBe(404);
  });

  it("read other records upstream without credentials", async () => {
    const bob = await createSubmitter();
    const carol = await createSubmitter();
    const id = await reserveAs(bob);
    await api(`/api/cve/${id}/cna`, { method: "POST", headers: bob.headers, body: record });
    const calls = mockUpstream({ method: "GET", path: `/api/cve/${id}`, status: 404, body: {} });
    const res = await api(`/api/cve/${id}`, { headers: carol.headers });
    expect(res.status).toBe(404);
    expect(calls[0]?.headers.has("CVE-API-KEY")).toBe(false);
  });

  it("ask for an ID to be rejected, and cannot change it once rejected", async () => {
    const bob = await createSubmitter();
    const id = await reserveAs(bob);
    const reasons = { cnaContainer: { rejectedReasons: [{ lang: "en", value: "Duplicate" }] } };
    const res = await api(`/api/cve/${id}/reject`, {
      method: "POST",
      headers: bob.headers,
      body: reasons,
    });
    expect(await res.json()).toMatchObject({ state: "in_review", revision: 1 });
    const calls = mockUpstream(aliceCheck, {
      method: "POST",
      path: `/api/cve/${id}/reject`,
      body: publish,
    });
    const approved = await api(`/api/cvedexd/cve/${id}/approve`, {
      method: "POST",
      headers: alice,
      body: { revision: 1 },
    });
    expect(approved.status).toBe(200);
    expect(JSON.parse(calls[1]!.body)).toEqual(reasons);
    const state = await api(`/api/cve-id/${id}`, { headers: bob.headers });
    expect(await state.json()).toMatchObject({ state: "REJECTED", cvedexd: { state: "rejected" } });
    const again = await api(`/api/cve/${id}/cna`, {
      method: "POST",
      headers: bob.headers,
      body: record,
    });
    expect(again.status).toBe(409);
    expect(await again.json()).toEqual({
      error: "BAD_STATE",
      message: `${id} is rejected and cannot change now`,
    });
  });

  it("see what CNA users do to their IDs directly", async () => {
    const bob = await createSubmitter();
    const id = await reserveAs(bob);
    const state = async () => {
      const res = await api(`/api/cve-id/${id}`, { headers: bob.headers });
      return (await res.json<{ state: string }>()).state;
    };
    mockUpstream(
      aliceCheck,
      { method: "POST", path: `/api/cve/${id}/cna`, body: publish },
      { method: "PUT", path: `/api/cve/${id}/reject`, body: publish },
      { method: "PUT", path: `/api/cve-id/${id}?state=RESERVED`, body: {} },
      { method: "PUT", path: `/api/cve-id/${id}?state=REJECTED`, body: {} },
      { method: "PUT", path: `/api/cve-id/${id}?org=other`, body: {} },
    );
    await api(`/api/cve/${id}/cna`, { method: "POST", headers: alice, body: record });
    expect(await state()).toBe("PUBLISHED");
    await api(`/api/cve/${id}/reject`, { method: "PUT", headers: alice, body: record });
    expect(await state()).toBe("REJECTED");
    await api(`/api/cve-id/${id}?state=RESERVED`, { method: "PUT", headers: alice });
    expect(await state()).toBe("RESERVED");
    await api(`/api/cve-id/${id}?state=REJECTED`, { method: "PUT", headers: alice });
    expect(await state()).toBe("REJECTED");
    await api(`/api/cve-id/${id}?org=other`, { method: "PUT", headers: alice });
    expect(await state()).toBe("REJECTED");
    const revisions = await env.DB.prepare(
      "SELECT revision, action FROM revisions WHERE cve_id = ? ORDER BY revision",
    )
      .bind(id)
      .all();
    expect(revisions.results).toEqual([
      { revision: 1, action: "publish" },
      { revision: 2, action: "reject" },
    ]);
    const refused = await api(`/api/cve-id/${id}?state=RESERVED`, {
      method: "PUT",
      headers: bob.headers,
    });
    expect(refused.status).toBe(403);
  });

  it("are refused everything else", async () => {
    const bob = await createSubmitter();
    const res = await api("/api/org/acme/users", { headers: bob.headers });
    expect(res.status).toBe(403);
  });
});
