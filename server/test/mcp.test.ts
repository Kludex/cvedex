import { describe, expect, it } from "vitest";
import {
  alice,
  aliceCheck,
  api,
  createAgent,
  createSubmitter,
  mockUpstream,
  publish,
  record,
  reserveAs,
} from "./helpers";

type ToolResult = { content: { type: string; text: string }[]; isError?: boolean };

async function rpc(
  headers: Record<string, string>,
  method: string,
  params: unknown = {},
  query = "",
): Promise<{ result: unknown }> {
  const res = await api(`/mcp${query}`, {
    method: "POST",
    headers: {
      ...headers,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: { jsonrpc: "2.0", id: 1, method, params },
  });
  expect(res.status).toBe(200);
  return res.json();
}

async function tool(
  headers: Record<string, string>,
  name: string,
  args: Record<string, unknown> = {},
): Promise<{ isError: boolean; body: unknown }> {
  const { result } = await rpc(headers, "tools/call", { name, arguments: args });
  const { content, isError } = result as ToolResult;
  return { isError: isError ?? false, body: JSON.parse(content[0]!.text) };
}

const cna = (record as { cnaContainer: Record<string, unknown> }).cnaContainer;

describe("mcp", () => {
  it("offers every tool, or only the read tools with read_only", async () => {
    const bob = await createSubmitter();
    const names = async (query: string) => {
      const { result } = await rpc(bob.headers, "tools/list", {}, query);
      return (result as { tools: { name: string }[] }).tools.map((t) => t.name);
    };
    expect(await names("")).toEqual([
      "list_cves",
      "show_cve",
      "reserve_ids",
      "publish_cve",
      "update_cve",
      "reject_cve",
    ]);
    expect(await names("?read_only=true")).toEqual(["list_cves", "show_cve"]);
  });

  it("signs callers in like the API, and only takes POST", async () => {
    const res = await api("/mcp", { method: "POST", body: {} });
    expect(res.status).toBe(401);
    const get = await api("/mcp");
    expect(get.status).toBe(405);
    expect(get.headers.get("allow")).toBe("POST");
  });

  it("lists a submitter's own IDs, filtered", async () => {
    const bob = await createSubmitter();
    const id = await reserveAs(bob);
    const listed = await tool(bob.headers, "list_cves", { state: "RESERVED", year: 2026 });
    expect(listed).toMatchObject({ isError: false, body: [{ cve_id: id, state: "RESERVED" }] });
    const none = await tool(bob.headers, "list_cves", { state: "PUBLISHED" });
    expect(none.body).toEqual([]);
  });

  it("follows every page of a CNA user's IDs, signing in once", async () => {
    const calls = mockUpstream(
      aliceCheck,
      {
        method: "GET",
        path: "/api/cve-id",
        body: { cve_ids: [{ cve_id: "CVE-2026-0001" }], nextPage: 2 },
      },
      {
        method: "GET",
        path: "/api/cve-id?page=2",
        body: { cve_ids: [{ cve_id: "CVE-2026-0002" }] },
      },
    );
    const listed = await tool(alice, "list_cves");
    expect(listed.body).toEqual([{ cve_id: "CVE-2026-0001" }, { cve_id: "CVE-2026-0002" }]);
    expect(calls.map((call) => call.path)).toEqual([
      aliceCheck.path,
      "/api/cve-id",
      "/api/cve-id?page=2",
    ]);
  });

  it("returns CVE Services errors as tool errors", async () => {
    mockUpstream(aliceCheck, {
      method: "GET",
      path: "/api/cve-id",
      status: 500,
      body: { error: "BOOM", message: "down" },
    });
    expect(await tool(alice, "list_cves")).toEqual({
      isError: true,
      body: { error: "BOOM", message: "down" },
    });
  });

  it("shows a record", async () => {
    mockUpstream(aliceCheck, { method: "GET", path: "/api/cve/CVE-2026-1100", body: publish });
    expect(await tool(alice, "show_cve", { cve_id: "CVE-2026-1100" })).toEqual({
      isError: false,
      body: publish,
    });
  });

  it("turns an agent's reservations into proposals", async () => {
    const bob = await createSubmitter();
    const agent = await createAgent(bob);
    const ids: string[] = [];
    for (const args of [
      { year: 2026 },
      { year: 2026, count: 2 },
      { year: 2026, count: 2, sequential: true },
    ]) {
      const reserved = await tool(agent.headers, "reserve_ids", args);
      expect(reserved.body).toMatchObject({ status: "pending_approval" });
      ids.push((reserved.body as { proposal_id: string }).proposal_id);
    }
    const res = await api("/api/cvedexd/proposals", { headers: bob.headers });
    const { proposals } = await res.json<{
      proposals: { id: string; method: string; path: string }[];
    }>();
    expect(proposals.map(({ id, method, path }) => ({ id, method, path }))).toEqual([
      { id: ids[0], method: "POST", path: "/api/cve-id?amount=1&cve_year=2026&short_name=acme" },
      {
        id: ids[1],
        method: "POST",
        path: "/api/cve-id?amount=2&cve_year=2026&short_name=acme&batch_type=nonsequential",
      },
      {
        id: ids[2],
        method: "POST",
        path: "/api/cve-id?amount=2&cve_year=2026&short_name=acme&batch_type=sequential",
      },
    ]);
  });

  it("sends a submitter's record to review", async () => {
    const bob = await createSubmitter();
    const id = await reserveAs(bob);
    expect(await tool(bob.headers, "publish_cve", { cve_id: id, cna_container: cna })).toEqual({
      isError: false,
      body: { message: `${id} was submitted for review`, state: "in_review", revision: 1 },
    });
  });

  it("updates a CNA user's record upstream", async () => {
    const calls = mockUpstream(aliceCheck, {
      method: "PUT",
      path: "/api/cve/CVE-2026-1100/cna",
      body: publish,
    });
    const updated = await tool(alice, "update_cve", {
      cve_id: "CVE-2026-1100",
      cna_container: cna,
    });
    expect(updated.isError).toBe(false);
    expect(JSON.parse(calls[1]!.body)).toEqual({ cnaContainer: cna });
    expect(calls[1]!.headers.get("CVE-API-KEY")).toBe("alice-key");
  });

  it("rejects with POST while reserved and PUT once published", async () => {
    const reason = { rejectedReasons: [{ lang: "en", value: "duplicate" }] };
    const calls = mockUpstream(
      aliceCheck,
      { method: "GET", path: "/api/cve-id/CVE-2026-0001", body: { state: "RESERVED" } },
      { method: "POST", path: "/api/cve/CVE-2026-0001/reject", body: {} },
      { method: "GET", path: "/api/cve-id/CVE-2026-0002", body: { state: "PUBLISHED" } },
      { method: "PUT", path: "/api/cve/CVE-2026-0002/reject", body: {} },
    );
    await tool(alice, "reject_cve", { cve_id: "CVE-2026-0001", reason: "duplicate" });
    await tool(alice, "reject_cve", { cve_id: "CVE-2026-0002", reason: "duplicate" });
    const writes = calls.filter((call) => call.path.endsWith("/reject"));
    expect(writes.map((call) => call.method)).toEqual(["POST", "PUT"]);
    expect(JSON.parse(writes[0]!.body)).toEqual({ cnaContainer: reason });
  });

  it("does not reject an ID it cannot find", async () => {
    const bob = await createSubmitter();
    const rejected = await tool(bob.headers, "reject_cve", {
      cve_id: "CVE-2026-99999",
      reason: "duplicate",
    });
    expect(rejected.isError).toBe(true);
  });
});
