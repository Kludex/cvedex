# cvedex

One repo, two deliverables:

- **`cvedex`** - a CVE Services client in Go: library, CLI, TUI, MCP server. Useful to any CNA on its own, like `cvelib` but in one static binary.
- **`cvedexd`** - a CNA policy server on Cloudflare Workers + D1, in TypeScript, under `server/`. It exposes the CVE Services API, so `cvedex` points at it unchanged, and adds review, audit and agent approval on top. It stores CVE records as opaque JSON and forwards them, so it shares no code with the client.

```
go.mod  install.sh  LICENSE  PLAN.md
cmd/ cveservices/ internal/   cvedex (Go)
testdata/recorded/   cassettes shared by both test suites
server/              cvedexd (TypeScript): wrangler.toml, package.json, src/, migrations/
.github/workflows/
  ci.yml             golangci-lint + go test, server vitest, on every PR
  release.yml        on v* tags: cross-compile, GitHub Release
  deploy.yml         on push to main touching server/**: wrangler d1 migrations apply, wrangler deploy
```

`server/` has no Go files, so `go get` ignores it. `deploy.yml` uses a Cloudflare API token scoped to Workers and D1 on one account; it is the only workflow that holds it.

## Two kinds of people

| | Who | Credential | Can |
| --- | --- | --- | --- |
| **CNA user** | A user of the org in CVE Services | Their own CVE Services key | Everything upstream allows, plus review and manage submitters in `cvedexd` |
| **Submitter** | A `cvedexd`-only account; does not exist in CVE Services | A `cvedexd` token | Reserve IDs, write records, submit for review |

CVE Services has no "reserve only" permission, so a submitter must never hold an upstream key. `cvedexd` reserves on their behalf with one service-account key and never publishes anything a CNA user has not approved.

`cvedexd` does not keep a list of CNA users. A request whose `CVE-API-KEY` is not a known submitter token is checked upstream with `GET /api/org/{org}/user/{user}`; if CVE Services accepts the credentials, the caller is a CNA user. One source of truth, no second password for reviewers, and approvals go upstream with the reviewer's own key so MITRE's records name the real person.

## Why the server mirrors the CVE Services API

If the server speaks the same API, the client is one codebase with one config value that changes: the base URL. `cvedex --url https://cveawg.mitre.org` for a CNA that wants no middle layer, `cvedex --url https://cve.yourorg` for one that does. The server accepts the same three auth headers. A CNA user sends exactly what they would send to MITRE; a submitter sends `CVE-API-USER` = submitter name, `CVE-API-KEY` = `cvedexd` token.

Same call, different outcome: `POST /api/cve/{id}/cna` publishes at MITRE, but at `cvedexd` it moves the record to `in_review`. The response body says which.

## cvedex (client)

### Layout

```
cmd/cvedex/           main
cveservices/          library: Client, typed errors, CVE IDs, orgs, cvedexd endpoints
internal/
  cli/                cobra commands
  tui/                bubbletea
  mcpserver/          MCP tools on the official go-sdk
  render/             lipgloss tables and the record summary
  config/             ~/.config/cvedex/config.json and env overrides
  cassette/           test server replaying testdata/recorded/
```

Records pass through as `json.RawMessage`: CVE Services validates them, and the client only reads the few fields it renders.

### Config

`~/.config/cvedex/config.json` written by `cvedex login`, overridden by `CVE_API_URL`, `CVE_API_ORG`, `CVE_API_USER`, `CVE_API_KEY`. These are the names `cvelib` uses, so existing CNA setups work with no changes.

### CLI

Covers the CVE Services surface a CNA uses day to day:

```
cvedex login [--test]                         prompts in a terminal; --org --user and the key on stdin otherwise
cvedex status                                 server, user, CNA (alias: ping, whoami)
cvedex reserve [--year 2026] [-n 1] [--sequential]
cvedex list [--state reserved|published|rejected]
cvedex show CVE-2026-0001
cvedex publish CVE-2026-0001 record.json      POST /api/cve/{id}/cna
cvedex update  CVE-2026-0001 record.json      PUT  /api/cve/{id}/cna
cvedex reject  CVE-2026-0001 --reason "..."
cvedex org | org users | org add-user <name> | org reset-key <name>
```

Every command takes `--json`, which prints the API response, and errors as the API's body on stderr. Text output is colored on a terminal only. IDs work without the `CVE-` prefix. `record.json` is a CNA container, bare, wrapped as `{"cnaContainer": ...}`, or a full record as `show --json` prints it; `-` reads stdin. Writes to MITRE production and `reset-key` ask for confirmation, or need `--yes` without a terminal. Non-zero exit on error.

Against `cvedexd` only, checked with `GET /api/health-check`:

```
cvedex review | review show <id> | review approve <id> | review request-changes <id> "note"
cvedex proposals | proposals approve <proposal-id> | proposals deny <proposal-id>
cvedex audit [--user name] [--since date]
cvedex submitter add <name> | submitter token <id> [--agent]
```

### MCP

Stdio, JSON-RPC 2.0. Tools map 1:1 to CLI commands: `list_cves`, `show_cve`, `reserve_ids`, `publish_cve`, `update_cve`. Write tools carry `destructiveHint`; read tools `readOnlyHint`. Against MITRE directly, the MCP client prompt is the only guard. Against `cvedexd` with an agent token, writes return `{status: "pending_approval", proposal_id}` and the human approves from the CLI or TUI.

### TUI

Tabs: CVE IDs (open a record, reserve), and against `cvedexd` review (read, approve), proposals (approve, deny) and audit. Every write asks y/n first.

## cvedexd (server)

Cloudflare Worker, D1 for storage. `hono` for routing and middleware. It moves to `tastapi` (`~/dev/personal/tastapi`) once that is ready. Secrets via `wrangler secret`: `CVE_API_URL`, `CVE_API_ORG`, `CVE_API_USER`, `CVE_API_KEY` for the service account that reserves IDs on behalf of submitters. That key is used for nothing else.

### Why a Worker

One CNA, a handful of people, a few requests a day. The server never parses a CVE record: it checks a token, writes an audit row, stores a blob, flips a state, forwards upstream. There is nothing in it that wants Go. On a Worker there is no machine, TLS, reverse proxy or backup job to own, and D1 is SQLite with point-in-time restore. The cost is one more language in the project, for about 500 lines.

If the server ever needs to be self-hosted, the same code runs on a VPS behind Caddy with `@hono/node-server` and a local SQLite file; the SQL does not change.

### Record states

```
reserved -> in_review -> published
     ^          |
     +----------+  (changes_requested, note stored)
```

### Endpoints

CVE Services-compatible, forwarded or reinterpreted:

| Method | Path | Server behaviour |
| --- | --- | --- |
| `POST` | `/api/cve-id` | Submitter: forward with the service key, record owner. CNA user: forward with their key. |
| `GET` | `/api/cve-id`, `/api/cve-id/{id}` | Submitter: own IDs. CNA user: all. |
| `GET` | `/api/cve/{id}` | Local record if any, else upstream |
| `POST` `PUT` | `/api/cve/{id}/cna` | Submitter: store record, state `in_review`, nothing reaches upstream. CNA user: forward with their key. |
| `*` | anything else under `/api/` | CNA user: forward with their key. Submitter: `403`. |
| `GET` | `/api/health-check` | Reports `cvedexd` and version, so the client enables extra commands |

Server-only, under `/api/cvedexd/`:

| Method | Path | Who | Effect |
| --- | --- | --- | --- |
| `GET` | `/review` | CNA user | Records in `in_review` |
| `POST` | `/cve/{id}/approve` | CNA user | Forwards the stored record upstream with the reviewer's key. State `published`. Upstream errors returned verbatim. |
| `POST` | `/cve/{id}/request-changes` `{note}` | CNA user | State `reserved`, note stored |
| `GET` | `/proposals` | submitter | Pending agent actions on own account |
| `POST` | `/proposals/{id}/approve` or `/deny` | submitter | Replays or discards |
| `GET` | `/audit?user=&since=` | CNA user | Audit rows |
| `POST` | `/submitters` `{name}` | CNA user | Creates submitter, returns first token |
| `POST` | `/submitters/{id}/tokens` `{kind}` | CNA user or self | New `user` or `agent` token |

### Agent approval

A `hono` middleware: a non-`GET` request with an `agent` token is stored as `{submitter, method, path, body}` and answered `202 {proposal_id}`. The submitter's `user` token approves and the server replays the request as them. Enforced server-side, so it holds even when the MCP client runs without permission prompts. Agent tokens exist only for submitters; a CNA user who wants an agent creates a submitter for it.

### Audit

A `hono` middleware, one insert-only table: `ts, actor, actor_kind (cna_user|submitter|agent), token_id, method, path, status, body_sha256, proposal_id`. Reviewer actions are rows like any other.

### Tables

`submitters`, `tokens`, `cves`, `proposals`, `audit`. One `schema.sql`, applied with `wrangler d1 migrations`.

## Dependencies

- `cvedex`: `net/http` with redirects disabled, so the key never follows a redirect. `cobra` for commands, Charm's `bubbletea`, `bubbles`, `lipgloss` and `huh` for the TUI, output and prompts, `modelcontextprotocol/go-sdk` for MCP.
- `cvedexd`: `hono`, `wrangler`. Tooling per the TypeScript rules: oxlint, oxc-format, `strict: true`.

## Phases

1. **`cvedex` core.** Library + CLI: `login reserve list show publish update ping`, `--json`. Already a usable CNA client for anyone.
2. **`cvedexd` reserve + audit.** Submitters, tokens, upstream credential check for CNA users, forwarded reservation, audit. Client needs no change.
3. **`cvedexd` review.** `in_review` on publish, approve, request-changes. Client gains the discovered commands.
4. **Agents.** Agent tokens, proposals, `cvedex mcp`.
5. **TUI.**

## Distribution

GitHub Releases. A workflow on `v*` tags runs `CGO_ENABLED=0 go build` for `x86_64-linux`, `aarch64-linux`, `x86_64-macos`, `aarch64-macos`, `x86_64-windows`, and uploads one archive per target plus a `SHA256SUMS`. Static binaries, so no libc dependency on Linux.

```sh
curl -fsSL https://raw.githubusercontent.com/Kludex/cvedex/main/install.sh | sh
```

`install.sh` detects OS and arch, downloads the latest release, verifies the checksum, and puts `cvedex` in `~/.local/bin`. Release notes come from the merged PRs since the previous tag.

As a library: `go get github.com/Kludex/cvedex/cveservices`.

Later, if people ask: a Homebrew tap and a `.deb`. Not before.

## Testing

- `cvedex` tests drive the CLI, TUI model and MCP server through their public entry points against `internal/cassette`, an `httptest` server that replays the recorded exchanges in order and fails on any other request. `cvedexd` endpoints have no recordings yet, so those tests use inline exchanges in the server's response shapes.
- `cvedexd` tests run under `@cloudflare/vitest-plugin` (the renamed `vitest-pool-workers`) against a real D1 binding, with upstream calls answered from fixtures by a stubbed `fetch`. 100% coverage is enforced.
- Cassettes live in `testdata/recorded/`, shared by both test suites, and come from `scripts/record-fixtures.mjs`. Each holds the request and the response's status, rate-limit and content headers, and raw body. Without credentials it records the public and error responses; with a test-instance CNA account it records the authenticated reads, and with `--writes` also a reservation and a publish. Tests only replay; CI never calls the test instance.
- CI runs `go test -race` on Linux, macOS and Windows.

## Not in v1

- CVE JSON 5.x schema validation client-side. Upstream validates; errors are shown verbatim.
- ADP containers.
- Per-user reservation quotas.
- MCP elicitation. The proposal queue covers approval for all clients.
- Multiple CNA orgs per `cvedexd`.
- Caching the upstream credential check. One extra upstream call per CNA-user request; cache when it hurts.
- Web UI.
