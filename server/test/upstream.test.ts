import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  alice,
  aliceCheck,
  api,
  createSubmitter,
  mockUpstream,
  record,
  reserveAs,
} from "./helpers";

describe("upstream", () => {
  it("does not follow redirects, so keys never leave CVE Services", async () => {
    const calls = mockUpstream(aliceCheck, {
      method: "GET",
      path: "/api/org/acme/users",
      status: 302,
      headers: { location: "https://attacker.test/" },
    });
    const res = await api("/api/org/acme/users", { headers: alice });
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({
      error: "UPSTREAM_REDIRECT",
      message: "CVE Services redirected to https://attacker.test/, which cvedexd does not follow",
    });
    expect(calls).toHaveLength(2);
  });

  it("refuses bodies over 1 MiB", async () => {
    const bob = await createSubmitter();
    const res = await api("/api/cve/CVE-2026-0001/cna", {
      method: "POST",
      headers: bob.headers,
      body: "x".repeat(1024 * 1024 + 1),
    });
    expect(res.status).toBe(413);
  });
});

describe("webhook", () => {
  const url = "https://hooks.test/cvedexd";

  afterEach(() => {
    delete env.WEBHOOK_URL;
  });

  it("is told when a record goes to review", async () => {
    env.WEBHOOK_URL = url;
    const bob = await createSubmitter();
    const id = await reserveAs(bob);
    const calls = mockUpstream({ url, method: "POST", path: "" });
    await api(`/api/cve/${id}/cna`, { method: "POST", headers: bob.headers, body: record });
    expect(JSON.parse(calls[0]!.body)).toEqual({
      text: `${bob.headers["CVE-API-USER"]} sent ${id} for review (publish, revision 1)`,
    });
  });

  it("never fails the request", async () => {
    env.WEBHOOK_URL = url;
    const bob = await createSubmitter();
    const id = await reserveAs(bob);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    mockUpstream({ url, method: "POST", path: "", status: 500 });
    const failing = await api(`/api/cve/${id}/cna`, {
      method: "POST",
      headers: bob.headers,
      body: record,
    });
    expect(failing.status).toBe(200);
    mockUpstream();
    const unreachable = await api(`/api/cve/${id}/cna`, {
      method: "PUT",
      headers: bob.headers,
      body: record,
    });
    expect(unreachable.status).toBe(200);
    expect(error.mock.calls.map(([line]) => JSON.parse(line as string).event)).toEqual([
      "webhook_failed",
      "webhook_failed",
    ]);
  });
});
