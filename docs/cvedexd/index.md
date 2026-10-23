# cvedexd

`cvedexd` is a server you put between your people and CVE Services. Maintainers reserve CVE IDs and write records. Your CNA's users review them, and only they publish.

## Why

CVE Services has no "reserve only" permission. A key that can reserve an ID can also publish any record of your CNA, or reject one.

So you cannot hand a key to every maintainer who needs a CVE ID. `cvedexd` holds one key that only reserves, and gives everyone else a token that cannot publish.

## Who is who

| | Who | Logs in with | Can |
| --- | --- | --- | --- |
| **CNA user** | A user of your CNA in CVE Services | Their own CVE Services key | Everything CVE Services allows them, plus review, audit and manage submitters |
| **Submitter** | Someone who needs IDs, such as a project maintainer | A `cvedexd` token | Reserve IDs, write records, send them for review |
| **Agent** | An AI agent working for a submitter | A `cvedexd` agent token | Ask for writes that wait until its submitter approves them |

`cvedexd` keeps no list of CNA users. It checks their credentials with CVE Services on every request, so there is no second password, and approvals reach MITRE under the reviewer's own name.

## How a CVE goes through it

```
        submitter                      CNA user
reserve ───────▶ reserved ──submit──▶ in_review ──approve──▶ published at MITRE
                    ▲                     │
                    └─request changes─────┘
```

1. The submitter [reserves an ID](submitters.md#reserve-an-id). `cvedexd` reserves it at MITRE with its own key, and remembers who it is for.
2. The submitter [writes the record](submitters.md#send-a-record-for-review). It stays in `cvedexd`. Nothing reaches MITRE.
3. A CNA user [reviews it](review.md). Approving publishes it with their key. Requesting changes sends it back with a note.

Everything is in the [audit log](review.md#audit).

## Same API, same client

`cvedexd` serves the CVE Services API. `cvedex` works against it with one change, the URL:

```sh
cvedex login --url https://cve.acme.org
```

The commands for review, proposals, audit and submitters work only against `cvedexd`.

## What it runs on

A [Cloudflare Worker](https://developers.cloudflare.com/workers/), with [D1](https://developers.cloudflare.com/d1/) for storage. There is no machine, TLS or backup job to look after. A CNA's traffic fits in the free plan.

Next: [deploy it](deploy.md).
