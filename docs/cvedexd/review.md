# Review

CNA users review what submitters send. Log in to `cvedexd` with your own CVE Services credentials:

```sh
cvedex login --url https://cve.acme.org
```

## See what is waiting

```console
$ cvedex review
CVE ID          ACTION    REV   SUBMITTER   SENT         TITLE
CVE-2026-1102   publish   2     bob         2026-10-22   Path traversal in widget's file server
CVE-2026-1099   reject    4     bob         2026-10-22   Path traversal in widget
```

`ACTION` is what approving does: `publish` publishes or updates the record, `reject` rejects the ID. `REV` counts the times the submitter sent this ID.

```console
$ cvedex review show CVE-2026-1102
CVE-2026-1102  revision 2 from bob, asking to publish

Path traversal in widget's file server

widget before 1.4.2 serves files outside its root when a path contains '..'.
...

Changes since the revision before

--- before
+++ now
@@ -3,7 +3,7 @@
-        "value": "widget serves files outside its root."
+        "value": "widget before 1.4.2 serves files outside its root when a path contains '..'."
...

Full record

{
  "title": "Path traversal in widget's file server",
  ...
}

Approve with cvedex review approve CVE-2026-1102 --revision 2
```

`show` prints the summary, what changed, and every field, so nothing hides from you:

- **What changed** compares against the revision you last saw, or, for a published ID, the record that is public now.
- **Every field** is printed as JSON, including ones the summary leaves out.
- **Control characters** in the record are printed as escapes such as `\x1b`, so a record cannot rewrite your terminal.

Add `--json` to get the record exactly as the submitter wrote it, under `record`, with `previous` and `published` beside it.

## Approve

Approve names the revision you read:

```console
$ cvedex review approve CVE-2026-1102 --revision 2
Approved CVE-2026-1102
```

`cvedexd` sends the record to MITRE with your key, so MITRE's history names you. If CVE Services rejects it, you get its errors, and the record stays in review.

!!! info "Why `--revision` is required"
    The submitter can send a new revision while you read the old one. If the revision changed, approving fails with `STALE_REVISION` and nothing is sent. Read it again, then approve the new revision.

Two reviewers cannot approve the same record twice. The first one claims it, the second gets `409`.

## Request changes

```console
$ cvedex review request-changes CVE-2026-1102 "Add the CWE." --revision 2
Sent CVE-2026-1102 back to its submitter.
```

The submitter [sees your note](submitters.md#when-a-reviewer-asks-for-changes) next to the ID until they send the record again.

## In the TUI

```sh
cvedex tui
```

The Review tab lists the same records. Press ++enter++ to read one, with what changed, and ++a++ to approve the revision you read.

## Get notified

Set `WEBHOOK_URL` and `cvedexd` posts a line there when a record is sent for review, approved or sent back, and when an agent proposes a write. See [Deploy](deploy.md#settings).

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

`STATUS` is `?` for a request that never finished, for example one that timed out. The entry is written before the request runs, so even a request that crashed `cvedexd` is in the log.

`audit` shows 500 entries at a time, newest first. When there are more, it prints the next command:

```console
$ cvedex audit
...
Older entries: cvedex audit --before 1520
```

The log is insert-only. `cvedexd` has no endpoint that changes or deletes it.

## Manage submitters

```console
$ cvedex submitter
ID   NAME   STATUS    OPEN IDS   TOKENS   CREATED
1    bob    enabled   2          2        2026-10-22
```

| Command | Does |
| --- | --- |
| `cvedex submitter` | Lists submitters, with their open IDs and live tokens |
| `cvedex submitter add <name>` | Creates a submitter and prints its first token |
| `cvedex submitter token <id>` | Issues another token for them |
| `cvedex submitter token <id> --agent` | Issues an [agent token](../agents.md#give-the-agent-its-own-token) for them |
| `cvedex submitter tokens <id>` | Lists their tokens, with when each was last used |
| `cvedex submitter revoke <token-id>` | Stops one token at once |
| `cvedex submitter disable <id>` | Stops all their tokens until you enable them again |
| `cvedex submitter enable <id>` | Lets them in again |

Revoking an agent token, or disabling its submitter, also denies the proposals it was waiting on. Records already in review stay there, for you to approve or send back.

!!! tip "Someone left, or a token leaked"
    `disable` first, it takes effect on the next request. Then look at `cvedex audit --user <name>` to see what the token did.

!!! info "Need an agent yourself?"
    Agent tokens belong to submitters. Create a submitter for the agent, and approve its proposals as that submitter.
