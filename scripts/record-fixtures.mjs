#!/usr/bin/env node
// Records CVE Services cassettes from the test instance into src/testdata/recorded/.
// Without credentials it records the public endpoints and the error responses. With CVE_API_ORG,
// CVE_API_USER and CVE_API_KEY set it also records the authenticated reads. With `--writes` it
// also reserves one ID and publishes a test record to it, which changes state on the test
// instance. It never calls reset_secret, and it writes nothing if the API key appears in a response.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const base = process.env.CVE_API_URL ?? "https://cveawg-test.mitre.org";
const out = join(import.meta.dirname, "..", "src", "testdata", "recorded");
const { CVE_API_ORG: org, CVE_API_USER: user, CVE_API_KEY: key } = process.env;
const authed = Boolean(org && user && key);
const writes = process.argv.includes("--writes");
const keptHeaders = /^(content-type|cache-control|retry-after|ratelimit-.*)$/;
const cassettes = new Map();

async function record(name, expected, method, path, { auth = false, headers = {}, body } = {}) {
  const sent = { ...headers };
  if (auth) Object.assign(sent, { "CVE-API-ORG": org, "CVE-API-USER": user, "CVE-API-KEY": key });
  if (body !== undefined) sent["content-type"] = "application/json";
  const res = await fetch(base + path, { method, headers: sent, body });
  const text = await res.text();
  if (res.status !== expected) throw new Error(`${method} ${path} returned ${res.status}, expected ${expected}`);
  const kept = Object.fromEntries([...res.headers].filter(([k]) => keptHeaders.test(k)).sort());
  const request = body === undefined ? { method, path } : { method, path, body };
  cassettes.set(name, { request, response: { status: res.status, headers: kept, body: text } });
  console.log(`${name} <- ${method} ${path} (${res.status})`);
  return text;
}

await record("health-check", 200, "GET", "/api/health-check");
await record("cve-2025-0001", 200, "GET", "/api/cve/CVE-2025-0001");
await record("cve-record-dne", 404, "GET", "/api/cve/CVE-2021-44228");
await record("unauthorized", 401, "GET", "/api/org/acme/user/ada", {
  headers: { "CVE-API-ORG": "acme", "CVE-API-USER": "ada", "CVE-API-KEY": "not-a-key" },
});

if (authed) {
  const enc = encodeURIComponent;
  await record("cve-id-list", 200, "GET", "/api/cve-id", { auth: true });
  await record("org", 200, "GET", `/api/org/${enc(org)}`, { auth: true });
  const me = JSON.parse(await record("user", 200, "GET", `/api/org/${enc(org)}/user/${enc(user)}`, { auth: true }));
  if (writes) {
    const year = new Date().getUTCFullYear();
    const reserved = JSON.parse(
      await record("reserve", 200, "POST", `/api/cve-id?amount=1&cve_year=${year}&short_name=${enc(org)}`, {
        auth: true,
      }),
    );
    const id = reserved.cve_ids[0].cve_id;
    await record("bad-request", 400, "POST", `/api/cve/${id}/cna`, {
      auth: true,
      body: JSON.stringify({ cnaContainer: {} }),
    });
    await record("publish", 200, "POST", `/api/cve/${id}/cna`, {
      auth: true,
      body: JSON.stringify({
        cnaContainer: {
          providerMetadata: { orgId: me.org_UUID },
          descriptions: [{ lang: "en", value: "cvedex fixture recording. Not a real vulnerability." }],
          affected: [{ vendor: "cvedex", product: "fixture", versions: [{ version: "0", status: "affected" }] }],
          references: [{ url: "https://github.com/Kludex/cvedex" }],
        },
      }),
    });
  }
} else if (writes) {
  throw new Error("--writes needs CVE_API_ORG, CVE_API_USER and CVE_API_KEY");
}

const serialized = [...cassettes].map(([name, c]) => [name, `${JSON.stringify(c, null, 2)}\n`]);
if (key && serialized.some(([, text]) => text.includes(key))) {
  throw new Error("the API key appears in a response; nothing was written");
}
mkdirSync(out, { recursive: true });
for (const [name, text] of serialized) writeFileSync(join(out, `${name}.json`), text);
