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
let placeholders = [];

async function record(name, expected, method, path, { auth = false, headers = {}, body } = {}) {
  const sent = { ...headers };
  if (auth) Object.assign(sent, { "CVE-API-ORG": org, "CVE-API-USER": user, "CVE-API-KEY": key });
  if (body !== undefined) sent["content-type"] = "application/json";
  const res = await fetchRetryingConnect(base + path, { method, headers: sent, body });
  const text = await res.text();
  if (res.status !== expected) throw new Error(`${method} ${path} returned ${res.status}, expected ${expected}`);
  const kept = Object.fromEntries([...res.headers].filter(([k]) => keptHeaders.test(k)).sort());
  const request = body === undefined ? { method, path } : { method, path, body };
  cassettes.set(name, { auth, cassette: { request, response: { status: res.status, headers: kept, body: text } } });
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
  const orgInfo = JSON.parse(await record("org", 200, "GET", `/api/org/${enc(org)}`, { auth: true }));
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
  await record("cve-id-list", 200, "GET", "/api/cve-id", { auth: true });
  // Longest first, so a full name is replaced before a short name it contains.
  placeholders = [
    [orgInfo.name, "Acme"],
    [enc(user), "alice%40acme.test"],
    [user, "alice@acme.test"],
    [orgInfo.UUID, "6f1e6c5e-2b1f-4a8a-9d3e-0c5f8f1a2b3c"],
    [me.UUID, "0b7d2c4e-9a1f-4e3b-8c6d-5f4a3b2c1d0e"],
    [org, "acme"],
    [me.name.first, "Alice"],
    [me.name.last, "Doe"],
  ].sort(([a], [b]) => b.length - a.length);
} else if (writes) {
  throw new Error("--writes needs CVE_API_ORG, CVE_API_USER and CVE_API_KEY");
}

// A connect timeout means nothing was sent, so even a POST is safe to retry.
async function fetchRetryingConnect(url, init, attempts = 5) {
  try {
    return await fetch(url, init);
  } catch (error) {
    if (attempts === 1 || error.cause?.code !== "UND_ERR_CONNECT_TIMEOUT") throw error;
    console.log(`connect timeout, retrying ${init.method} ${url}`);
    return fetchRetryingConnect(url, init, attempts - 1);
  }
}

const serialized = [...cassettes].map(([name, { auth, cassette }]) => {
  let text = `${JSON.stringify(cassette, null, 2)}\n`;
  if (auth) for (const [real, placeholder] of placeholders) text = text.replaceAll(real, placeholder);
  return [name, text];
});
const leaks = [key, ...placeholders.map(([real]) => real)].filter(Boolean);
if (serialized.some(([, text]) => leaks.some((secret) => text.includes(secret)))) {
  throw new Error("the API key or account details appear in a cassette; nothing was written");
}
mkdirSync(out, { recursive: true });
for (const [name, text] of serialized) writeFileSync(join(out, `${name}.json`), text);
