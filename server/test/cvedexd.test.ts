import { describe, expect, it } from "vitest";
import {
  alice,
  aliceCheck,
  api,
  badRequest,
  createAgent,
  createSubmitter,
  mockUpstream,
  publish,
  record,
  reserveAs,
  reserved,
  type Credentials,
} from "./helpers";

async function submitForReview(bob: Credentials): Promise<string> {
  const id = await reserveAs(bob);
  await api(`/api/cve/${id}/cna`, { method: "POST", headers: bob.headers, body: record });
  return id;
}

describe("review", () => {
  it("lists records in review to CNA users", async () => {
    const bob = await createSubmitter();
    const id = await submitForReview(bob);
    mockUpstream(aliceCheck);
    const res = await api("/api/cvedexd/review", { headers: alice });
    const { cves } = await res.json<{ cves: { cve_id: string; submitter: string }[] }>();
    expect(cves).toContainEqual(
      expect.objectContaining({ cve_id: id, submitter: bob.headers["CVE-API-USER"], record }),
    );
    const local = await api(`/api/cve/${id}`, { headers: alice });
    expect(await local.json()).toEqual(record);
  });

  it("is refused to submitters", async () => {
    const bob = await createSubmitter();
    const res = await api("/api/cvedexd/review", { headers: bob.headers });
    expect(res.status).toBe(403);
  });

  it("approval publishes upstream with the reviewer's key", async () => {
    const bob = await createSubmitter();
    const id = await submitForReview(bob);
    const calls = mockUpstream(aliceCheck, {
      method: "POST",
      path: `/api/cve/${id}/cna`,
      body: publish,
    });
    const res = await api(`/api/cvedexd/cve/${id}/approve`, { method: "POST", headers: alice });
    expect(await res.json()).toEqual(publish);
    expect(calls[1]?.headers.get("CVE-API-USER")).toBe("alice@acme.test");
    expect(JSON.parse(calls[1]!.body)).toEqual(record);

    const state = await api(`/api/cve-id/${id}`, { headers: bob.headers });
    expect(await state.json()).toMatchObject({
      state: "PUBLISHED",
      cvedexd: { state: "published" },
    });
  });

  it("approval of an update to a published record uses PUT", async () => {
    const bob = await createSubmitter();
    const id = await submitForReview(bob);
    mockUpstream(aliceCheck, { method: "POST", path: `/api/cve/${id}/cna`, body: publish });
    await api(`/api/cvedexd/cve/${id}/approve`, { method: "POST", headers: alice });
    await api(`/api/cve/${id}/cna`, { method: "PUT", headers: bob.headers, body: record });
    const calls = mockUpstream(aliceCheck, {
      method: "PUT",
      path: `/api/cve/${id}/cna`,
      body: publish,
    });
    const res = await api(`/api/cvedexd/cve/${id}/approve`, { method: "POST", headers: alice });
    expect(res.status).toBe(200);
    expect(calls[1]?.method).toBe("PUT");
  });

  it("returns upstream rejections verbatim and keeps the record in review", async () => {
    const bob = await createSubmitter();
    const id = await submitForReview(bob);
    mockUpstream(aliceCheck, {
      method: "POST",
      path: `/api/cve/${id}/cna`,
      status: 400,
      body: badRequest,
    });
    const res = await api(`/api/cvedexd/cve/${id}/approve`, { method: "POST", headers: alice });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(badRequest);
    const state = await api(`/api/cve-id/${id}`, { headers: bob.headers });
    expect(await state.json()).toMatchObject({ cvedexd: { state: "in_review" } });
  });

  it("request-changes sends the record back with a note", async () => {
    const bob = await createSubmitter();
    const id = await submitForReview(bob);
    mockUpstream(aliceCheck);
    const missing = await api(`/api/cvedexd/cve/${id}/request-changes`, {
      method: "POST",
      headers: alice,
      body: {},
    });
    expect(missing.status).toBe(400);
    const res = await api(`/api/cvedexd/cve/${id}/request-changes`, {
      method: "POST",
      headers: alice,
      body: { note: "Add a CWE" },
    });
    expect(await res.json()).toEqual({ cve_id: id, state: "reserved", note: "Add a CWE" });
    const state = await api(`/api/cve-id/${id}`, { headers: bob.headers });
    expect(await state.json()).toMatchObject({ cvedexd: { state: "reserved", note: "Add a CWE" } });

    const again = await api(`/api/cvedexd/cve/${id}/approve`, { method: "POST", headers: alice });
    expect(again.status).toBe(404);
  });

  it("rejects a body that is not JSON", async () => {
    mockUpstream(aliceCheck);
    const res = await api("/api/cvedexd/cve/CVE-2026-0001/request-changes", {
      method: "POST",
      headers: alice,
      body: "nope",
    });
    expect(res.status).toBe(400);
  });
});

describe("submitters", () => {
  it("are created by CNA users with a first token", async () => {
    mockUpstream(aliceCheck);
    const res = await api("/api/cvedexd/submitters", {
      method: "POST",
      headers: alice,
      body: { name: "dave" },
    });
    expect(res.status).toBe(201);
    const body = await res.json<{ name: string; kind: string; token: string }>();
    expect(body).toMatchObject({ name: "dave", kind: "user" });
    expect(body.token).toMatch(/^cvedexd_/);

    const duplicate = await api("/api/cvedexd/submitters", {
      method: "POST",
      headers: alice,
      body: { name: "dave" },
    });
    expect(duplicate.status).toBe(409);

    const invalid = await api("/api/cvedexd/submitters", {
      method: "POST",
      headers: alice,
      body: { name: "no spaces" },
    });
    expect(invalid.status).toBe(400);
  });

  it("cannot create submitters", async () => {
    const bob = await createSubmitter();
    const res = await api("/api/cvedexd/submitters", {
      method: "POST",
      headers: bob.headers,
      body: { name: "x" },
    });
    expect(res.status).toBe(403);
  });

  it("get new tokens from CNA users or themselves only", async () => {
    const bob = await createSubmitter();
    const carol = await createSubmitter();
    mockUpstream(aliceCheck);
    const byCna = await api(`/api/cvedexd/submitters/${bob.id}/tokens`, {
      method: "POST",
      headers: alice,
      body: { kind: "user" },
    });
    expect(byCna.status).toBe(201);
    const byOther = await api(`/api/cvedexd/submitters/${bob.id}/tokens`, {
      method: "POST",
      headers: carol.headers,
      body: { kind: "user" },
    });
    expect(byOther.status).toBe(403);
    const badKind = await api(`/api/cvedexd/submitters/${bob.id}/tokens`, {
      method: "POST",
      headers: alice,
      body: { kind: "root" },
    });
    expect(badKind.status).toBe(400);
    const unknown = await api("/api/cvedexd/submitters/999999/tokens", {
      method: "POST",
      headers: alice,
      body: { kind: "user" },
    });
    expect(unknown.status).toBe(404);
  });
});

describe("agents", () => {
  it("can read without approval", async () => {
    const bob = await createSubmitter();
    const agent = await createAgent(bob);
    const res = await api("/api/cve-id", { headers: agent.headers });
    expect(res.status).toBe(200);
    const head = await api("/api/cve-id", { method: "HEAD", headers: agent.headers });
    expect(head.status).toBe(200);
  });

  it("writes become proposals the submitter approves", async () => {
    const bob = await createSubmitter();
    const agent = await createAgent(bob);
    const calls = mockUpstream();
    const res = await api("/api/cve-id?amount=1&cve_year=2026", {
      method: "POST",
      headers: agent.headers,
    });
    expect(res.status).toBe(202);
    const { status, proposal_id } = await res.json<{ status: string; proposal_id: string }>();
    expect(status).toBe("pending_approval");
    expect(calls).toEqual([]);

    const agentList = await api("/api/cvedexd/proposals", { headers: agent.headers });
    expect(agentList.status).toBe(403);
    const list = await api("/api/cvedexd/proposals", { headers: bob.headers });
    expect(await list.json()).toMatchObject({
      proposals: [{ id: proposal_id, method: "POST", path: "/api/cve-id?amount=1&cve_year=2026" }],
    });

    mockUpstream({
      method: "POST",
      path: "/api/cve-id?amount=1&cve_year=2026&short_name=acme",
      body: reserved("CVE-2026-88888"),
    });
    const approved = await api(`/api/cvedexd/proposals/${proposal_id}/approve`, {
      method: "POST",
      headers: bob.headers,
    });
    expect(approved.status).toBe(200);
    const ids = await api("/api/cve-id", { headers: bob.headers });
    expect(await ids.json()).toMatchObject({ cve_ids: [{ cve_id: "CVE-2026-88888" }] });

    const twice = await api(`/api/cvedexd/proposals/${proposal_id}/approve`, {
      method: "POST",
      headers: bob.headers,
    });
    expect(twice.status).toBe(404);
  });

  it("proposals with a body replay it", async () => {
    const bob = await createSubmitter();
    const agent = await createAgent(bob);
    const id = await reserveAs(bob);
    const res = await api(`/api/cve/${id}/cna`, {
      method: "POST",
      headers: agent.headers,
      body: record,
    });
    const { proposal_id } = await res.json<{ proposal_id: string }>();
    const approved = await api(`/api/cvedexd/proposals/${proposal_id}/approve`, {
      method: "POST",
      headers: bob.headers,
    });
    expect(await approved.json()).toMatchObject({ state: "in_review" });
  });

  it("denied proposals are discarded", async () => {
    const bob = await createSubmitter();
    const agent = await createAgent(bob);
    const res = await api("/api/cve-id?amount=1", { method: "POST", headers: agent.headers });
    const { proposal_id } = await res.json<{ proposal_id: string }>();
    const denied = await api(`/api/cvedexd/proposals/${proposal_id}/deny`, {
      method: "POST",
      headers: bob.headers,
    });
    expect(await denied.json()).toEqual({ id: proposal_id, status: "denied" });
  });
});

it("unknown cvedexd endpoints are 404", async () => {
  mockUpstream(aliceCheck);
  const res = await api("/api/cvedexd/nothing", { headers: alice });
  expect(res.status).toBe(404);
});
