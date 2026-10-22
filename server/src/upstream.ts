import type { AppContext, CveHeaders } from "./env";

export async function upstream(
  c: AppContext,
  headers: Partial<CveHeaders>,
  method: string,
  path: string,
  body?: string,
): Promise<Response> {
  const init: RequestInit = { method, headers: { ...headers } };
  if (body) {
    init.headers = { ...headers, "content-type": "application/json" };
    init.body = body;
  }
  const res = await fetch(`${c.env.CVE_API_URL}${path}`, init);
  return new Response(res.body, res);
}

export async function forward(c: AppContext, headers: Partial<CveHeaders>): Promise<Response> {
  const url = new URL(c.req.url);
  return upstream(c, headers, c.req.method, url.pathname + url.search, await c.req.text());
}

export function serviceHeaders(c: AppContext): CveHeaders {
  return {
    "CVE-API-ORG": c.env.CVE_API_ORG,
    "CVE-API-USER": c.env.CVE_API_USER,
    "CVE-API-KEY": c.env.CVE_API_KEY,
  };
}
