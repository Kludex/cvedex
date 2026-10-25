# cvedex

One repo, two deliverables:

- **`cvedex`** - a CVE Services client in Go: library, CLI, TUI. Useful to any CNA on its own, like `cvelib` but in one static binary.
- **`cvedexd`** - a CNA policy server on Cloudflare Workers + D1, in TypeScript, under `server/`. It exposes the CVE Services API, so `cvedex` points at it unchanged, and adds review, audit and agent approval on top. It stores CVE records as opaque JSON and forwards them, so it shares no code with the client.

```
go.mod  install.sh  LICENSE  PLAN.md
cmd/ cveservices/ internal/   cvedex (Go)
testdata/recorded/   cassettes shared by both test suites
docs/, zensical.toml user docs, built with Zensical
wrangler.toml        the cvedex-docs Worker that serves them
server/              cvedexd (TypeScript): wrangler.toml, package.json, src/, migrations/
.github/workflows/
  ci.yml             golangci-lint + go test, server vitest, on every PR
  release.yml        on v* tags: cross-compile, attest provenance, GitHub Release, deploy docs
  deploy.yml         on push to main touching server/**: wrangler d1 migrations apply, wrangler deploy
```

`server/` has no Go files, so `go get` ignores it. The Cloudflare token that deploys `cvedexd` and the docs lives in the `cloudflare` GitHub environment, limited to `main` and `v*` tags. Docs previews on pull requests use a separate `docs-preview` environment and token, so a pull request never reaches the deploy token.

## Two kinds of people

| | Who | Credential | Can |
| --- | --- | --- | --- |
| **CNA user** | A user of the org in CVE Services | Their own CVE Services key | Everything upstream allows, plus review and manage submitters in `cvedexd` |
| **Submitter** | A `cvedexd`-only account; does not exist in CVE Services | A `cvedexd` token | Reserve IDs, write records, submit for review |

CVE Services has no "reserve only" permission, so a submitter must never hold an upstream key. `cvedexd` reserves on their behalf with one service-account key and never publishes anything a CNA user has not approved.

`cvedexd` does not keep a list of CNA users. A request whose `CVE-API-KEY` is not a `cvedexd_` token, and whose `CVE-API-ORG` is the org `cvedexd` serves, is checked upstream with `GET /api/org/{org}/user/{user}`; if CVE Services accepts the credentials, the caller is a CNA user. These checks are rate-limited per IP, so `cvedexd` is no oracle for guessing keys. One source of truth, no second password for reviewers, and approvals go upstream with the reviewer's own key so MITRE's records name the real person.

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
  render/             lipgloss tables and the record summary
  record/             the CVE JSON 5 schema check, and records built from GitHub advisories
  config/             ~/.config/cvedex/config.json, the key in the OS keychain, and env overrides
  cassette/           test server replaying testdata/recorded/
```

Records pass through as `json.RawMessage`, and the client only reads the few fields it renders. Before `publish`, `update` or a TUI save sends one, `internal/record` checks it against the bundled CNA container schema from `CVEProject/cve-schema` v5.2.0 (CC0), so a broken record fails before the network, with every problem listed. It adds a placeholder `providerMetadata` first, since CVE Services fills that in. The newest schema keeps the check no stricter than MITRE's.

### Config

`~/.config/cvedex/config.json` written by `cvedex login`, with the API key in the OS keychain through `zalando/go-keyring` (stored under service `cvedex`, account `<user> on <url>`), or in the `0600` file when there is no keychain. Overridden by `CVE_API_URL`, `CVE_API_ORG`, `CVE_API_USER`, `CVE_API_KEY`. These are the names `cvelib` uses, so existing CNA setups work with no changes.

### CLI

Covers the CVE Services surface a CNA uses day to day:

```
cvedex login [--test]                         prompts in a terminal; --org --user and the key on stdin otherwise
cvedex logout                                 deletes the config and the keychain entry
cvedex status                                 server, user, CNA (alias: ping, whoami)
cvedex reserve [--year 2026] [-n 1] [--sequential]
cvedex list [--state s] [--year y] [--reserved-after/-before t] [--modified-after/-before t]
cvedex show CVE-2026-0001
cvedex publish CVE-2026-0001 record.json      POST /api/cve/{id}/cna
cvedex update  CVE-2026-0001 record.json      PUT  /api/cve/{id}/cna
cvedex reject  CVE-2026-0001 --reason "..."   POST /api/cve/{id}/reject, or PUT once published
cvedex reject  CVE-2026-0001 --id-only | unreject CVE-2026-0001    PUT /api/cve-id/{id}?state=
cvedex adp     CVE-2026-0001 adp.json         PUT  /api/cve/{id}/adp
cvedex record from-advisory <GHSA URL>        a CNA container from a GitHub repository advisory, on stdout
cvedex record check record.json               the schema check alone, without credentials
cvedex org | org quota | org users | org add-user <name> | org update-user <name> | org reset-key <name>
```

Every command takes `--json`, which prints the API response, and errors as JSON on stderr: the API's body, or `{"error", "message", "details"}` in the same shape for the client's own (`INVALID_RECORD`, `NOT_LOGGED_IN`, `PENDING_APPROVAL`, `CVEDEX_ERROR`). Text output is colored on a terminal only, and control characters from the server are printed as escapes. Server URLs must be https, except to loopback. A `429` is retried after `Retry-After`, three times at most. IDs work without the `CVE-` prefix. `record.json` is a CNA container, bare, wrapped as `{"cnaContainer": ...}`, or a full record as `show --json` prints it; `-` reads stdin. Writes to MITRE production and `reset-key` ask for confirmation, or need `--yes` without a terminal. Non-zero exit on error.

Against `cvedexd` only, checked with `GET /api/health-check`:

```
cvedex review | review show <id> | review approve <id> --revision n | review request-changes <id> "note" --revision n
cvedex proposals | proposals show <id> | proposals approve <id> | proposals deny <id>
cvedex audit [--user name] [--since date] [--before id]
cvedex submitter | submitter add <name> | submitter disable|enable <id>
cvedex submitter token <id> [--agent] | submitter tokens <id> | submitter revoke <token-id>
```

`record from-advisory` maps a repository advisory, drafts included with `GH_TOKEN`, the way GitHub's own CNA does: summary to a title led by the repo name ("widget: ..."), description, one `affected` entry per package with the range as `version`/`lessThan(OrEqual)` and the ecosystem's `versionType`, CWEs, CVSS 3.x and 4.0 metrics, credits, and references (the advisory, then the description's links). A range it cannot express is kept verbatim. It warns on stderr when the result fails the schema check. The TUI's `i` does the same into a draft.

`review show` prints a summary, a diff against the previous revision or the published record, and the full JSON, so a field the summary leaves out cannot hide.

### MCP

Served by `cvedexd` at `POST /mcp`, Streamable HTTP, stateless, with JSON responses. Remote, so agents running in the cloud can use it and nothing is installed next to the agent. Signed in with the same three headers as the API; no OAuth, so clients that only support OAuth cannot connect.

Tools map 1:1 to CLI commands: `list_cves`, `show_cve`, `reserve_ids`, `publish_cve`, `update_cve`, `reject_cve`. Each calls `cvedexd`'s own routes in-process as the signed-in actor (the `REPLAY` binding, as proposal approval does), so quota, audit, review and proposals apply unchanged, and a CNA user is checked upstream once per MCP request rather than once per inner call. Write tools carry `destructiveHint`; read tools `readOnlyHint`. `/mcp?read_only=true` offers only the read tools, because a published record is untrusted text that can carry instructions for the agent. With a CNA user's key, the MCP client prompt is the only guard. With an agent token, writes return `{status: "pending_approval", proposal_id}` and the human approves from the CLI or TUI.

### TUI

Tabs: CVE IDs (open a record, edit, reserve), and against `cvedexd` review (read with the diff, approve the revision read), proposals (read, approve, deny) and audit. Every write asks y/n first.

`e` opens the CNA container in `$VISUAL` or `$EDITOR`, without the `providerMetadata` CVE Services fills in, or a template for a reserved ID. On save it asks to publish or update. A draft the API rejects is kept and reopens on the next `e`, with the validation errors shown under it. Quitting with unsent drafts asks, then deletes them.

## cvedexd (server)

Cloudflare Worker, D1 for storage. `hono` for routing and middleware. It moves to `tastapi` (`~/dev/personal/tastapi`) once that is ready. Secrets via `wrangler secret`: `CVE_API_ORG`, `CVE_API_USER`, `CVE_API_KEY` for the service account that reserves IDs on behalf of submitters, and an optional `WEBHOOK_URL`. That key is used for nothing else. Variables: `CVE_API_URL`, and `MAX_OPEN_IDS`, the unpublished IDs one submitter may hold. Bodies over 1 MiB are refused, and upstream redirects are never followed.

### Why a Worker

One CNA, a handful of people, a few requests a day. The server never parses a CVE record: it checks a token, writes an audit row, stores a blob, flips a state, forwards upstream. There is nothing in it that wants Go. On a Worker there is no machine, TLS, reverse proxy or backup job to own, and D1 is SQLite with point-in-time restore. The cost is one more language in the project, for about 500 lines.

If the server ever needs to be self-hosted, the same code runs on a VPS behind Caddy with `@hono/node-server` and a local SQLite file; the SQL does not change.

### Record states

```
reserved -> in_review -> publishing -> published or rejected
     ^          |                         |
     +----------+  (note stored)          +--> in_review again (update or reject)
```

Each submission carries an `action`, `publish` or `reject`, and bumps the ID's `revision`; every revision is kept in `revisions`. Approve names the revision the reviewer read and atomically moves the ID to `publishing`, so a newer revision or a second reviewer gets `409`. A reviewer's note sends the record back to `reserved`. The client shows that ID as "changes requested", with the note, until the submitter sends it again. Direct writes by CNA users to a tracked ID update its state too.

### Endpoints

CVE Services-compatible, forwarded or reinterpreted:

| Method | Path | Server behaviour |
| --- | --- | --- |
| `POST` | `/api/cve-id` | Submitter: forward with the service key, record owner. CNA user: forward with their key. |
| `GET` | `/api/cve-id`, `/api/cve-id/{id}` | Submitter: own IDs. CNA user: all. |
| `GET` | `/api/cve/{id}` | Local record if any, else upstream |
| `POST` `PUT` | `/api/cve/{id}/cna`, `/api/cve/{id}/reject` | Submitter: store record and action, state `in_review`, nothing reaches upstream. CNA user: forward with their key. |
| `*` | anything else under `/api/` | CNA user: forward with their key. Submitter: `403`. |
| `GET` | `/api/health-check` | Reports `cvedexd` and version, so the client enables extra commands |

Server-only, under `/api/cvedexd/`:

| Method | Path | Who | Effect |
| --- | --- | --- | --- |
| `GET` | `/review` | CNA user | Records in `in_review`, with the previous revision and the published record |
| `POST` | `/cve/{id}/approve` `{revision}` | CNA user | Forwards the stored record or rejection upstream with the reviewer's key. Upstream errors returned verbatim, and the ID goes back to `in_review`. |
| `POST` | `/cve/{id}/request-changes` `{note, revision}` | CNA user | State `reserved`, note stored |
| `GET` | `/proposals` | submitter | Pending agent actions on own account |
| `POST` | `/proposals/{id}/approve` or `/deny` | submitter | Replays or discards |
| `GET` | `/audit?user=&since=&before=` | CNA user | Audit rows, 500 a page, with the `next` cursor |
| `GET` `POST` | `/submitters` | CNA user | Lists submitters, or creates one and returns its first token |
| `POST` | `/submitters/{id}/disable` or `/enable` | CNA user | Refuses or accepts their tokens; disabling denies their pending proposals |
| `GET` `POST` | `/submitters/{id}/tokens` | CNA user or self | Lists tokens, or issues a `user` or `agent` one |
| `GET` | `/published` | anyone | Published IDs of the CNA, from upstream `state=PUBLISHED` with the service key, every page. Cached 10 minutes, so anonymous traffic cannot drive upstream calls. For a public advisory index such as marcelotryle.com/cna. |
| `DELETE` | `/tokens/{id}` | CNA user or owner | Revokes a token and denies its pending proposals |

### Agent approval

A `hono` middleware: a non-`GET` request with an `agent` token is stored as `{submitter, method, path, body}` and answered `202 {proposal_id}`, up to 50 pending per submitter. The submitter's `user` token approves and the server replays the request as them. Enforced server-side, so it holds even when the MCP client runs without permission prompts. Agent tokens exist only for submitters; a CNA user who wants an agent creates a submitter for it.

### Audit

A `hono` middleware, one insert-only table: `ts, actor, actor_kind (cna_user|submitter|agent), token_id, method, path, status, body_sha256, proposal_id`. The row is written before the request runs and its status filled in after, so a request that dies still leaves a row, with a `null` status. Reviewer actions are rows like any other. An optional webhook hears about submissions, decisions and proposals.

### Tables

`submitters`, `tokens`, `cves`, `revisions`, `proposals`, `audit`. Schema changes are numbered files in `server/migrations/`, applied with `wrangler d1 migrations apply`.

## Dependencies

- `cvedex`: `net/http` with redirects disabled, so the key never follows a redirect. `cobra` for commands, Charm's `bubbletea`, `bubbles`, `lipgloss` and `huh` for the TUI, output and prompts, `zalando/go-keyring` for the key and `santhosh-tekuri/jsonschema` for the schema check (both pure Go, so static builds keep working).
- `cvedexd`: `hono`, `wrangler`, `@modelcontextprotocol/sdk` and `zod` for MCP. Tooling per the TypeScript rules: oxlint, oxc-format, `strict: true`.

## Phases

1. **`cvedex` core.** Library + CLI: `login reserve list show publish update ping`, `--json`. Already a usable CNA client for anyone.
2. **`cvedexd` reserve + audit.** Submitters, tokens, upstream credential check for CNA users, forwarded reservation, audit. Client needs no change.
3. **`cvedexd` review.** `in_review` on publish, approve, request-changes. Client gains the discovered commands.
4. **Agents.** Agent tokens, proposals, remote MCP at `/mcp`.
5. **TUI.**

## Distribution

GitHub Releases. A workflow on `v*` tags runs `CGO_ENABLED=0 go build` for `x86_64-linux`, `aarch64-linux`, `x86_64-macos`, `aarch64-macos`, `x86_64-windows`, attests their build provenance, and uploads one archive per target plus a `SHA256SUMS`. Static binaries, so no libc dependency on Linux.

```sh
curl -fsSL https://raw.githubusercontent.com/Kludex/cvedex/main/install.sh | sh
```

`install.sh` detects OS and arch, downloads the latest release, verifies the checksum, checks the provenance with `gh attestation verify` when `gh` is logged in, and puts `cvedex` in `~/.local/bin`. Release notes come from the merged PRs since the previous tag.

As a library: `go get github.com/Kludex/cvedex/cveservices`.

Later, if people ask: a Homebrew tap and a `.deb`. Not before.

## Testing

- `cvedex` tests drive the CLI and TUI model through their public entry points against `internal/cassette`, an `httptest` server that replays the recorded exchanges in order and fails on any other request. `cvedexd` endpoints have no recordings yet, so those tests use inline exchanges in the server's response shapes.
- `cvedexd` tests run under `@cloudflare/vitest-plugin` (the renamed `vitest-pool-workers`) against a real D1 binding, with upstream calls answered from fixtures by a stubbed `fetch`. 100% coverage is enforced.
- Cassettes live in `testdata/recorded/`, shared by both test suites, and come from `scripts/record-fixtures.mjs`. Each holds the request and the response's status, rate-limit and content headers, and raw body. Without credentials it records the public and error responses; with a test-instance CNA account it records the authenticated reads, with `--writes` also a reservation and a publish, and with `--lifecycle` the ID state changes, both rejects and a user update. `--only=a,b` rewrites just those cassettes. Tests only replay; CI never calls the test instance.
- CI runs `go test -race` on Linux, macOS and Windows, and enforces 100% coverage of `cveservices/` and `internal/` on Linux. The prompts and `cvedex tui` are tested in a pseudo-terminal, which Windows skips.

## Docs

User docs live in `docs/`, built with [Zensical](https://zensical.org). Preview them with `uvx zensical serve`. Like Starlette's, they are served by a static-assets Worker, `cvedex-docs` in the root `wrangler.toml`: `release.yml` deploys them on each `v*` tag, so they match the released binary, and same-repo PRs get a preview URL from `wrangler versions upload`. They cover the client by task (log in, publish, org, TUI, agents, scripting, library) and `cvedexd` (why, deploy, submitters, review, API), with examples taken from real runs against the test instance.

## Not in v1

- Per-CNA-user reservation quotas. Submitters have `MAX_OPEN_IDS`.
- A Windows install script. The release zip and `gh attestation verify` cover it.
- MCP elicitation. The proposal queue covers approval for all clients.
- Multiple CNA orgs per `cvedexd`.
- Caching the upstream credential check. One extra upstream call per CNA-user request; cache when it hurts.
- Web UI.
