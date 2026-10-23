import { env, exports } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import unauthorized from "../../testdata/recorded/unauthorized.json";
import {
  alice,
  aliceCheck,
  api,
  cassette,
  createAgent,
  createSubmitter,
  mockUpstream,
} from "./helpers";

describe("health", () => {
  it("reports cvedexd and its version without credentials", async () => {
    const res = await api("/api/health-check");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ server: "cvedexd", version: "0.1.0" });
  });
});

describe("authentication", () => {
  it("rejects a request without credentials", async () => {
    const res = await api("/api/cve-id");
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({
      error: "UNAUTHORIZED",
      message: "CVE-API-USER and CVE-API-KEY headers are required",
    });
  });

  it("rejects an unknown user without an org", async () => {
    const res = await api("/api/cve-id", {
      headers: { "CVE-API-USER": "mallory", "CVE-API-KEY": "x" },
    });
    expect(res.status).toBe(401);
  });

  it("returns the upstream rejection verbatim", async () => {
    const rejected = cassette(unauthorized);
    const calls = mockUpstream({ ...rejected, path: aliceCheck.path });
    const res = await api("/api/cve-id", { headers: alice });
    expect(res.status).toBe(401);
    expect(await res.text()).toBe(rejected.body);
    expect(calls[0]?.headers.get("CVE-API-KEY")).toBe("alice-key");
  });

  it("does not accept a submitter token under another name", async () => {
    const bob = await createSubmitter();
    const res = await api("/api/cve-id", {
      headers: { ...bob.headers, "CVE-API-USER": "someone-else", "CVE-API-ORG": "" },
    });
    expect(res.status).toBe(401);
  });
});

describe("sign-in", () => {
  it("refuses users of other CNAs without asking CVE Services", async () => {
    const calls = mockUpstream();
    const res = await api("/api/cvedexd/review", {
      headers: { ...alice, "CVE-API-ORG": "evilcna", "CVE-API-USER": "mallory@evil.test" },
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: "NOT_ALLOWED",
      message: "This cvedexd serves acme only",
    });
    expect(calls).toEqual([]);
  });

  it("works without a client IP", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const refused = await exports.default.fetch(new Request("https://cvedexd.test/api/cve-id"));
    expect(refused.status).toBe(401);
    expect(JSON.parse(warn.mock.calls[0]![0] as string)).toMatchObject({ ip: null });
    mockUpstream(aliceCheck);
    const res = await exports.default.fetch(
      new Request("https://cvedexd.test/api/cvedexd/review", { headers: alice }),
    );
    expect(res.status).toBe(200);
  });

  it("is rate limited per client IP", async () => {
    mockUpstream(aliceCheck);
    const headers = { ...alice, "CF-Connecting-IP": "192.0.2.1" };
    const statuses = [];
    for (let i = 0; i < 61; i++) {
      statuses.push((await api("/api/cvedexd/review", { headers })).status);
    }
    expect(statuses.slice(0, 60).every((status) => status === 200)).toBe(true);
    expect(statuses[60]).toBe(429);
  });
});

describe("audit", () => {
  it("records authenticated requests and logs refused ones", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const before = await env.DB.prepare("SELECT max(id) AS id FROM audit").first<{ id: number }>();
    await api("/api/cve-id", {
      headers: { "CVE-API-USER": "eve", "CVE-API-KEY": "", "CF-Connecting-IP": "192.0.2.9" },
    });
    const after = await env.DB.prepare("SELECT max(id) AS id FROM audit").first<{ id: number }>();
    expect(after?.id).toBe(before?.id);
    expect(JSON.parse(warn.mock.calls[0]![0] as string)).toEqual({
      event: "sign_in_refused",
      status: 401,
      user: "eve",
      org: null,
      ip: "192.0.2.9",
      method: "GET",
      path: "/api/cve-id",
    });

    const bob = await createSubmitter();
    await api("/api/cve-id?state=RESERVED", { headers: bob.headers });
    const row = await env.DB.prepare(
      "SELECT actor, actor_kind, method, path, status FROM audit ORDER BY id DESC LIMIT 1",
    ).first();
    expect(row).toEqual({
      actor: bob.headers["CVE-API-USER"],
      actor_kind: "submitter",
      method: "GET",
      path: "/api/cve-id?state=RESERVED",
      status: 200,
    });
  });

  it("stores a body hash, never the body", async () => {
    const bob = await createSubmitter();
    await createAgent(bob);
    const row = await env.DB.prepare(
      "SELECT actor, actor_kind, token_id, body_sha256 FROM audit ORDER BY id DESC LIMIT 1",
    ).first<{ actor: string; actor_kind: string; token_id: number; body_sha256: string }>();
    expect(row?.actor).toBe(bob.headers["CVE-API-USER"]);
    expect(row?.actor_kind).toBe("submitter");
    expect(row?.token_id).toBeTypeOf("number");
    expect(row?.body_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is insert-only", async () => {
    await api("/api/health-check");
    await api("/api/cve-id");
    await expect(env.DB.prepare("DELETE FROM audit").run()).rejects.toThrow(/insert-only/);
    await expect(env.DB.prepare("UPDATE audit SET status = 200").run()).rejects.toThrow(
      /insert-only/,
    );
    await expect(env.DB.prepare("UPDATE audit SET path = '/'").run()).rejects.toThrow(
      /insert-only/,
    );
  });

  it("pages from the newest entry back", async () => {
    await env.DB.batch(
      Array.from({ length: 501 }, () =>
        env.DB.prepare(
          "INSERT INTO audit (actor, actor_kind, method, path, status) VALUES ('page', 'agent', 'GET', '/', 200)",
        ),
      ),
    );
    mockUpstream(aliceCheck);
    const first = await api("/api/cvedexd/audit?user=page", { headers: alice });
    const page = await first.json<{ audit: { id: number }[]; next: number }>();
    expect(page.audit).toHaveLength(500);
    expect(page.next).toBe(page.audit.at(-1)!.id);
    const second = await api(`/api/cvedexd/audit?user=page&before=${page.next}`, {
      headers: alice,
    });
    const rest = await second.json<{ audit: { id: number }[]; next: number | null }>();
    expect(rest.audit).toHaveLength(1);
    expect(rest.next).toBeNull();
  });

  it("lets CNA users filter by user and date", async () => {
    const bob = await createSubmitter();
    await api("/api/cve-id", { headers: bob.headers });
    mockUpstream(aliceCheck);
    const user = encodeURIComponent(bob.headers["CVE-API-USER"]!);
    const res = await api(`/api/cvedexd/audit?user=${user}&since=2000-01-01`, { headers: alice });
    const { audit } = await res.json<{ audit: { actor: string }[] }>();
    expect(audit.length).toBeGreaterThan(0);
    expect(audit.every((row) => row.actor === bob.headers["CVE-API-USER"])).toBe(true);

    const all = await api("/api/cvedexd/audit", { headers: alice });
    expect((await all.json<{ audit: unknown[] }>()).audit.length).toBeGreaterThan(audit.length);
  });

  it("is not visible to submitters", async () => {
    const bob = await createSubmitter();
    const res = await api("/api/cvedexd/audit", { headers: bob.headers });
    expect(res.status).toBe(403);
  });
});
