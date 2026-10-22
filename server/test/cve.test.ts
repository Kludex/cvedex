import { describe, expect, it } from "vitest";
import badRequest from "./fixtures/bad-request.json";
import cveIdList from "./fixtures/cve-id-list.json";
import published from "../../src/testdata/recorded/cve-2025-0001.json";
import recordDne from "../../src/testdata/recorded/cve-record-dne.json";
import publish from "./fixtures/publish.json";
import record from "./fixtures/record.json";
import {
  alice,
  aliceCheck,
  api,
  cassette,
  createSubmitter,
  cveIdFor,
  mockUpstream,
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
      cvedexd: { state: "reserved", note: null },
    });
  });

  it("get upstream reservation errors verbatim and own nothing", async () => {
    const bob = await createSubmitter();
    mockUpstream({
      method: "POST",
      path: "/api/cve-id?amount=0&short_name=acme",
      status: 400,
      body: badRequest,
    });
    const res = await api("/api/cve-id?amount=0", { method: "POST", headers: bob.headers });
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

  it("are refused everything else", async () => {
    const bob = await createSubmitter();
    const res = await api("/api/org/acme/users", { headers: bob.headers });
    expect(res.status).toBe(403);
  });
});
