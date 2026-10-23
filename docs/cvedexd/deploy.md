# Deploy

You need a [Cloudflare account](https://dash.cloudflare.com/sign-up), Node.js, and a CVE Services user for `cvedexd` to reserve IDs with.

!!! tip "Give cvedexd its own CVE Services user"
    Ask your CNA's admin for a user that is not an admin, and use it for nothing else. `cvedexd` only uses its key to reserve IDs for submitters. If that key leaks, reset it, and your people's keys are untouched.

## Deploy from your machine

```sh
git clone https://github.com/Kludex/cvedex
cd cvedex/server
npm ci
npx wrangler login
npx wrangler d1 create cvedexd
```

`d1 create` prints a `database_id`. Put it in `wrangler.toml`:

```toml title="server/wrangler.toml" hl_lines="4"
[[d1_databases]]
binding = "DB"
database_name = "cvedexd"
database_id = "4f1d2c3e-..."
migrations_dir = "migrations"
```

Create the tables, store the service user's credentials, and deploy:

```sh
npx wrangler d1 migrations apply DB --remote
npx wrangler secret put CVE_API_ORG
npx wrangler secret put CVE_API_USER
npx wrangler secret put CVE_API_KEY
npx wrangler deploy
```

`wrangler deploy` prints the URL, such as `https://cvedexd.acme.workers.dev`. Check it:

```console
$ cvedex --url https://cvedexd.acme.workers.dev status
Server     ● https://cvedexd.acme.workers.dev  cvedexd 0.1.0
```

To use your own domain, add a [custom domain](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/) to the Worker.

## Point it at the test instance first

`CVE_API_URL` in `wrangler.toml` is MITRE production. Set it to the test instance while you try things:

```toml title="server/wrangler.toml"
[vars]
CVE_API_URL = "https://cveawg-test.mitre.org"
```

The service user and your CNA users then need test-instance accounts.

## Settings

Variables go under `[vars]` in `wrangler.toml`. Secrets go in with `npx wrangler secret put <NAME>`.

| Name | Kind | Default | Meaning |
| --- | --- | --- | --- |
| `CVE_API_URL` | Variable | `https://cveawg.mitre.org` | The CVE Services `cvedexd` talks to |
| `MAX_OPEN_IDS` | Variable | `10` | How many unpublished IDs one submitter may hold |
| `CVE_API_ORG`, `CVE_API_USER`, `CVE_API_KEY` | Secrets | | The service user that reserves IDs. `CVE_API_ORG` is also the only CNA whose users may sign in |
| `WEBHOOK_URL` | Secret, optional | | A Slack-compatible incoming webhook. `cvedexd` posts `{"text": "..."}` to it about reviews and proposals |

The `AUTH_LIMITER` [rate limit](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) in `wrangler.toml` caps CNA user sign-ins at 60 a minute per client IP, so nobody can use `cvedexd` to guess keys at MITRE.

!!! tip "Also rate-limit at the edge"
    The binding counts per Cloudflare location. For a hard limit across all of them, add a [rate limiting rule](https://developers.cloudflare.com/waf/rate-limiting-rules/) on your custom domain, for example 100 requests per 10 seconds per IP on `/api/`.

## Deploy from GitHub Actions

`.github/workflows/deploy.yml` runs the checks and tests, applies migrations and deploys on every push to `main` that touches `server/`.

Create a GitHub environment named `cloudflare`, with two secrets:

| Secret | Value |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | An API token with the account permissions Workers Scripts: Edit and D1: Edit |
| `CLOUDFLARE_ACCOUNT_ID` | Your account ID, from the Workers dashboard |

Under **Deployment branches and tags**, allow only `main` and `v*` tags. A workflow on any other branch then cannot read the token.

The `CVE_API_*` secrets stay in Cloudflare. GitHub never sees them.

## Run it locally

```sh
cd server
cat > .dev.vars <<'EOF'
CVE_API_URL=https://cveawg-test.mitre.org
CVE_API_ORG=acme
CVE_API_USER=cvedexd@acme.org
CVE_API_KEY=...
EOF
npx wrangler d1 migrations apply DB --local
npm run dev
```

It listens on `http://localhost:8787`, with a local D1 database under `.wrangler/`. `.dev.vars` is gitignored.

## Upgrade

Pull, then deploy again. Apply migrations before the code that needs them:

```sh
git pull
npx wrangler d1 migrations apply DB --remote
npx wrangler deploy
```

D1 [Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/) can restore the database to any minute of the last 7 days on the free plan, or 30 on a paid one.
