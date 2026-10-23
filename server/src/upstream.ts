import type { AppContext, CveHeaders } from "./env";

export async function upstream(
  c: AppContext,
  headers: Partial<CveHeaders>,
  method: string,
  path: string,
  body?: string,
): Promise<Response> {
  const init: RequestInit = { method, headers: { ...headers }, redirect: "manual" };
  if (body) {
    init.headers = { ...headers, "content-type": "application/json" };
    init.body = body;
  }
  const res = await fetch(`${c.env.CVE_API_URL}${path}`, init);
  if (res.status >= 300 && res.status < 400) {
    return Response.json(
      {
        error: "UPSTREAM_REDIRECT",
        message: `CVE Services redirected to ${res.headers.get("location")}, which cvedexd does not follow`,
      },
      { status: 502 },
    );
  }
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

/** Tells the webhook, if any, about `text`. A failing webhook never fails the request. */
export async function notify(c: AppContext, text: string): Promise<void> {
  if (!c.env.WEBHOOK_URL) {
    return;
  }
  try {
    const res = await fetch(c.env.WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
      redirect: "manual",
    });
    if (!res.ok) {
      console.error(JSON.stringify({ event: "webhook_failed", status: res.status }));
    }
  } catch (err) {
    console.error(JSON.stringify({ event: "webhook_failed", error: String(err) }));
  }
}
