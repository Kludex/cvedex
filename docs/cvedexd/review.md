# Review

CNA users review what submitters send. Log in to `cvedexd` with your own CVE Services credentials:

```sh
cvedex login --url https://cve.acme.org
```

## See what is waiting

```console
$ cvedex review
CVE ID          SUBMITTER   SENT         TITLE
CVE-2026-1102   bob         2026-10-22   Path traversal in widget's file server

$ cvedex review show CVE-2026-1102
CVE-2026-1102  from bob

Path traversal in widget's file server

widget before 1.4.2 serves files outside its root when a path contains '..'.
...
```

Add `--json` to `review show` to get the record exactly as the submitter wrote it, under `record`.

## Approve

```console
$ cvedex review approve CVE-2026-1102
Published CVE-2026-1102
```

`cvedexd` sends the record to MITRE with your key, so MITRE's history names you. If CVE Services rejects it, you get its errors, and the record stays in review.

## Request changes

```console
$ cvedex review request-changes CVE-2026-1102 "Add the CWE."
Sent CVE-2026-1102 back to its submitter.
```

The submitter [sees your note](submitters.md#when-a-reviewer-asks-for-changes) next to the ID until they send the record again.

## In the TUI

```sh
cvedex tui
```

The Review tab lists the same records. Press ++enter++ to read one and ++a++ to approve it.

## Audit

Every request is logged: who, as what, which endpoint, and the response status.

```console
$ cvedex audit --since 2026-10-22
TIME                  ACTOR            AS          REQUEST                                                   STATUS
2026-10-22 22:10:41   alice@acme.org   cna_user    POST /api/cvedexd/cve/CVE-2026-1102/approve               200
2026-10-22 22:08:05   bob              submitter   POST /api/cve/CVE-2026-1102/cna                           200
2026-10-22 22:08:05   bob              submitter   POST /api/cve-id?amount=1&cve_year=2026&short_name=acme   200
2026-10-22 22:07:56   bob              agent       POST /api/cve-id?amount=1&cve_year=2026&short_name=acme   202
```

Filter with `--user` and `--since`. `--json` adds the proposal ID of agent writes. The database also keeps which token made each request and the SHA-256 of its body.

The log is insert-only. `cvedexd` has no endpoint that changes or deletes it.

## Manage submitters

| Command | Does |
| --- | --- |
| `cvedex submitter add <name>` | Creates a submitter and prints its first token |
| `cvedex submitter token <id>` | Issues another token for them |
| `cvedex submitter token <id> --agent` | Issues an [agent token](../agents.md#give-the-agent-its-own-token) for them |

!!! info "Need an agent yourself?"
    Agent tokens belong to submitters. Create a submitter for the agent, and approve its proposals as that submitter.
