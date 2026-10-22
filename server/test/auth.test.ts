import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import unauthorized from "../../src/testdata/recorded/unauthorized.json";
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

describe("audit", () => {
  it("records every request, including rejected ones", async () => {
    await api("/api/cve-id", { headers: { "CVE-API-USER": "eve", "CVE-API-KEY": "" } });
    await api("/api/cve-id");
    const { results } = await env.DB.prepare(
      "SELECT actor, actor_kind, method, path, status FROM audit ORDER BY id DESC LIMIT 2",
    ).all();
    expect(results).toEqual([
      { actor: null, actor_kind: null, method: "GET", path: "/api/cve-id", status: 401 },
      { actor: "eve", actor_kind: null, method: "GET", path: "/api/cve-id", status: 401 },
    ]);
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
