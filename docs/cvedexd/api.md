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
| Anything else | A CNA user, if CVE Services accepts the credentials |

## CVE Services endpoints

| Method | Path | Submitter or agent | CNA user |
| --- | --- | --- | --- |
| `POST` | `/api/cve-id` | Reserves with the service key, for your CNA | Forwarded with your key |
| `GET` | `/api/cve-id` | Your own IDs | Forwarded |
| `GET` | `/api/cve-id/{id}` | Your own ID | Forwarded |
| `GET` | `/api/cve/{id}` | Your record in review, else MITRE's | The record in review, else MITRE's |
| `POST`, `PUT` | `/api/cve/{id}/cna` | Stores the record, state `in_review` | Forwarded |
| any | anything else under `/api/` | `403` | Forwarded |
| `GET` | `/api/health-check` | `{"server": "cvedexd", "version": "0.1.0"}` | Same |

A submitter's `POST /api/cve/{id}/cna` answers:

```json
{"message": "CVE-2026-1102 was submitted for review", "state": "in_review"}
```

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
| `POST` | `/cve/{id}/approve` | CNA user | Publishes the record at MITRE with your key |
| `POST` | `/cve/{id}/request-changes` | CNA user | Sends it back, with body `{"note": "..."}` |
| `GET` | `/proposals` | Submitter | Your agent's pending writes |
| `POST` | `/proposals/{id}/approve` | Submitter | Sends the write as you |
| `POST` | `/proposals/{id}/deny` | Submitter | Discards it |
| `GET` | `/audit?user=&since=` | CNA user | The audit log, newest first |
| `POST` | `/submitters` | CNA user | Creates a submitter, with body `{"name": "bob"}` |
| `POST` | `/submitters/{id}/tokens` | CNA user, or that submitter | Issues a token, with body `{"kind": "user"}` or `{"kind": "agent"}` |

## Agent writes

Any request but a `GET` or `HEAD` made with an agent token is held, and answered `202`:

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
| `401` | `UNAUTHORIZED` | Unknown token, or CVE Services refused the credentials |
| `403` | `NOT_ALLOWED` | Your role cannot do this |
| `404` | `CVEID_NOT_FOUND`, `PROPOSAL_NOT_FOUND`, `SUBMITTER_NOT_FOUND`, `NOT_FOUND` | No such ID, proposal, submitter or endpoint |
| `409` | `SUBMITTER_EXISTS` | The submitter name is taken |

Errors from CVE Services pass through as it sent them.
