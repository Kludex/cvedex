# API

`cvedexd` serves the [CVE Services API](https://cveawg.mitre.org/api-docs/) and a few endpoints of its own. Any CVE Services client works against it.

## Authentication

The same three headers as CVE Services:

```sh
curl https://cve.acme.org/api/cve-id \
  -H "CVE-API-ORG: acme" \
  -H "CVE-API-USER: bob" \
  -H "CVE-API-KEY: cvedexd_q3Jx..."
```

| `CVE-API-KEY` is | You are |
| --- | --- |
| A `cvedexd` user token, with `CVE-API-USER` its submitter's name | A submitter |
| A `cvedexd` agent token | An agent |
| Anything else | A CNA user, if `CVE-API-ORG` is the CNA `cvedexd` serves and CVE Services accepts the credentials |

A key that starts with `cvedexd_` but matches no live token gets `401`, and is never sent to CVE Services.

CNA user sign-ins are checked with CVE Services, 60 a minute per client IP at most. Past that, they get `429`.

## CVE Services endpoints

| Method | Path | Submitter or agent | CNA user |
| --- | --- | --- | --- |
| `POST` | `/api/cve-id` | Reserves with the service key, for your CNA | Forwarded with your key |
| `GET` | `/api/cve-id` | Your own IDs | Forwarded |
| `GET` | `/api/cve-id/{id}` | Your own ID | Forwarded |
| `GET` | `/api/cve/{id}` | Your record in review, else MITRE's | The record in review, else MITRE's |
| `POST`, `PUT` | `/api/cve/{id}/cna` | Stores the record for review, to publish or update | Forwarded |
| `POST`, `PUT` | `/api/cve/{id}/reject` | Stores the rejection for review | Forwarded |
| any | anything else under `/api/` | `403` | Forwarded |
| `GET` | `/api/health-check` | `{"server": "cvedexd", "version": "0.1.0"}` | Same |

A submitter's `POST /api/cve/{id}/cna` answers:

```json
{"message": "CVE-2026-1102 was submitted for review", "state": "in_review", "revision": 2}
```

It answers `409 BAD_STATE` while a reviewer is publishing the ID, or once it is rejected.

The IDs a submitter lists carry where they are in review:

```json
{
  "cve_id": "CVE-2026-1102",
  "state": "RESERVED",
  "cvedexd": {"state": "reserved", "note": "Add the CWE."}
}
```

## cvedexd endpoints

Under `/api/cvedexd/`:

| Method | Path | Who | Does |
| --- | --- | --- | --- |
| `GET` | `/review` | CNA user | Records in review |
| `POST` | `/cve/{id}/approve` | CNA user | Publishes or rejects at MITRE with your key, with body `{"revision": 2}` |
| `POST` | `/cve/{id}/request-changes` | CNA user | Sends it back, with body `{"note": "...", "revision": 2}` |
| `GET` | `/proposals` | Submitter | Your agent's pending writes |
| `POST` | `/proposals/{id}/approve` | Submitter | Sends the write as you |
| `POST` | `/proposals/{id}/deny` | Submitter | Discards it |
| `GET` | `/audit?user=&since=&before=` | CNA user | The audit log, newest first |
| `GET` | `/submitters` | CNA user | Submitters, with their open IDs and live tokens |
| `POST` | `/submitters` | CNA user | Creates a submitter, with body `{"name": "bob"}` |
| `POST` | `/submitters/{id}/disable` | CNA user | Refuses all their tokens, denies their pending proposals |
| `POST` | `/submitters/{id}/enable` | CNA user | Accepts their tokens again |
| `GET` | `/submitters/{id}/tokens` | CNA user, or that submitter | Their tokens, without the secrets |
| `POST` | `/submitters/{id}/tokens` | CNA user, or that submitter | Issues a token, with body `{"kind": "user"}` or `{"kind": "agent"}` |
| `DELETE` | `/tokens/{id}` | CNA user, or the token's submitter | Revokes it, and denies the proposals it made |
| `GET` | `/published` | Anyone | Your CNA's published CVE IDs |

`POST /mcp` serves the same tools to AI agents over MCP, signed in with the headers above. See [AI agents](../agents.md).

### Published IDs

`GET /api/cvedexd/published` needs no headers. It is there so a website can list your CNA's CVEs without holding any credentials:

```console
$ curl https://cve.acme.org/api/cvedexd/published
["CVE-2026-1099","CVE-2026-1101"]
```

`cvedexd` asks CVE Services with the service account, so the list includes CVEs published without going through `cvedexd`. Fetch each record from the public `https://cveawg.mitre.org/api/cve/{id}`.

!!! info "Up to 10 minutes behind"
    The answer is cached for 10 minutes, so anonymous visitors cannot make `cvedexd` call CVE Services more often than that.

### Review items

Each item of `GET /review`:

```json
{
  "cve_id": "CVE-2026-1102",
  "submitter": "bob",
  "action": "publish",
  "revision": 2,
  "updated_at": "2026-10-22T22:08:05.000Z",
  "record": {"title": "..."},
  "previous": {"title": "..."},
  "published": null
}
```

`previous` is the revision before this one, and `published` the record that is public now. Either is `null` when there is none.

### Audit pages

`GET /audit` answers 500 entries at most, and the `id` to pass as `before` for the next page:

```json
{"audit": [{"id": 1520, "ts": "...", "actor": "bob", "actor_kind": "submitter", "method": "POST", "path": "/api/cve-id", "status": 200}], "next": 1519}
```

`next` is `null` on the last page. `status` is `null` for a request that never finished.

## Agent writes

Any request but a `GET` or `HEAD` made with an agent token is held, and answered `202`. A submitter can have 50 pending proposals at most:

```json
{"status": "pending_approval", "proposal_id": "ac543563-2473-4437-8fe7-6460a79a18a0"}
```

The submitter then approves or denies it under `/api/cvedexd/proposals/`.

## Errors

The CVE Services error shape, with `cvedexd`'s own codes:

```json
{"error": "NOT_ALLOWED", "message": "Submitters can only reserve IDs and submit records"}
```

| Status | `error` | When |
| --- | --- | --- |
| `400` | `BAD_INPUT` | A body or parameter is wrong |
| `401` | `UNAUTHORIZED` | Unknown or revoked token, disabled submitter, or CVE Services refused the credentials |
| `403` | `NOT_ALLOWED` | Your role cannot do this, or your org is not the one `cvedexd` serves |
| `403` | `EXCEEDED_ID_QUOTA` | A submitter would hold more than `MAX_OPEN_IDS` open IDs |
| `404` | `CVEID_NOT_FOUND`, `PROPOSAL_NOT_FOUND`, `SUBMITTER_NOT_FOUND`, `TOKEN_NOT_FOUND`, `NOT_FOUND` | No such ID, proposal, submitter, token or endpoint |
| `409` | `SUBMITTER_EXISTS` | The submitter name is taken |
| `409` | `STALE_REVISION` | The record changed since the revision you reviewed |
| `409` | `BAD_STATE` | The ID cannot change in its current state |
| `413` | `BAD_INPUT` | The body is larger than 1 MiB |
| `429` | `RATE_LIMITED` | Too many CNA user sign-ins from your IP |
| `429` | `TOO_MANY_PROPOSALS` | The agent's submitter has 50 proposals to decide first |
| `502` | `UPSTREAM_REDIRECT` | CVE Services answered with a redirect, which `cvedexd` does not follow |

Errors from CVE Services pass through as it sent them.
