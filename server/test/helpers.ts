import { exports } from "cloudflare:workers";
import { afterEach, vi } from "vitest";
import badRequestCassette from "../../src/testdata/recorded/bad-request.json";
import cveIdListCassette from "../../src/testdata/recorded/cve-id-list.json";
import publishCassette from "../../src/testdata/recorded/publish.json";
import reserveCassette from "../../src/testdata/recorded/reserve.json";
import userCassette from "../../src/testdata/recorded/user.json";

export type Upstream = {
  method: string;
  path: string;
  status?: number;
  headers?: Record<string, string>;
  body?: unknown;
};

export type Cassette = {
  request: { method: string; path: string };
  response: { status: number; headers: Record<string, string>; body: string };
};

/** An upstream route that answers exactly what `scripts/record-fixtures.mjs` recorded. */
export function cassette({ request, response }: Cassette): Upstream & { body: string } {
  return { ...request, ...response };
}

type CveIdList = { cve_ids: { cve_id: string }[] };

export const record: unknown = JSON.parse(publishCassette.request.body);
export const publish: unknown = JSON.parse(publishCassette.response.body);
export const badRequest: unknown = JSON.parse(badRequestCassette.response.body);
export const cveIdList: CveIdList = JSON.parse(cveIdListCassette.response.body);
const reservation: CveIdList = JSON.parse(reserveCassette.response.body);

export type Call = { method: string; path: string; headers: Headers; body: string };

afterEach(() => {
  vi.restoreAllMocks();
});

export function mockUpstream(...routes: Upstream[]): Call[] {
  const calls: Call[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const path = url.pathname + url.search;
    calls.push({
      method: request.method,
      path,
      headers: request.headers,
      body: await request.text(),
    });
    const route = routes.find((r) => r.method === request.method && r.path === path);
    if (!route || url.origin !== "https://cveawg.test") {
      throw new Error(`unexpected upstream request: ${request.method} ${request.url}`);
    }
    const reply = { status: route.status ?? 200, headers: route.headers ?? {} };
    return typeof route.body === "string"
      ? new Response(route.body, reply)
      : Response.json(route.body ?? {}, reply);
  });
  return calls;
}

export const alice = {
  "CVE-API-ORG": "acme",
  "CVE-API-USER": "alice@acme.test",
  "CVE-API-KEY": "alice-key",
};

export const aliceCheck: Upstream = cassette(userCassette);

export function api(
  path: string,
  init: { method?: string; headers?: Record<string, string>; body?: unknown } = {},
): Promise<Response> {
  const body =
    init.body === undefined || typeof init.body === "string"
      ? init.body
      : JSON.stringify(init.body);
  return exports.default.fetch(
    new Request(`https://cvedexd.test${path}`, {
      method: init.method ?? "GET",
      headers: init.headers ?? {},
      body,
    }),
  );
}

let sequence = 0;

export function uniqueName(prefix: string): string {
  sequence += 1;
  return `${prefix}-${Date.now()}-${sequence}`;
}

export function cveIdFor(n: number): string {
  return `CVE-2026-${String(n).padStart(5, "0")}`;
}

export function reserved(cveId: string) {
  return {
    ...reservation,
    cve_ids: reservation.cve_ids.map((entry) => ({ ...entry, cve_id: cveId })),
  };
}

export type Credentials = { id: number; headers: Record<string, string> };

export async function createSubmitter(): Promise<Credentials> {
  const name = uniqueName("bob");
  mockUpstream(aliceCheck);
  const res = await api("/api/cvedexd/submitters", {
    method: "POST",
    headers: alice,
    body: { name },
  });
  const { id, token } = await res.json<{ id: number; token: string }>();
  vi.restoreAllMocks();
  return { id, headers: { "CVE-API-ORG": "whatever", "CVE-API-USER": name, "CVE-API-KEY": token } };
}

export async function createAgent(submitter: Credentials): Promise<Credentials> {
  const res = await api(`/api/cvedexd/submitters/${submitter.id}/tokens`, {
    method: "POST",
    headers: submitter.headers,
    body: { kind: "agent" },
  });
  const { token } = await res.json<{ token: string }>();
  return { id: submitter.id, headers: { ...submitter.headers, "CVE-API-KEY": token } };
}

let cveCounter = Math.floor(Math.random() * 90000);

export async function reserveAs(submitter: Credentials): Promise<string> {
  cveCounter += 1;
  const cveId = cveIdFor(cveCounter);
  mockUpstream({
    method: "POST",
    path: "/api/cve-id?amount=1&cve_year=2026&short_name=acme",
    body: reserved(cveId),
  });
  await api("/api/cve-id?amount=1&cve_year=2026&short_name=whatever", {
    method: "POST",
    headers: submitter.headers,
  });
  vi.restoreAllMocks();
  return cveId;
}
