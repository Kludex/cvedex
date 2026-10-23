# Submitters

A submitter is someone who needs CVE IDs but should not publish them, such as the maintainer of a project your CNA covers. They exist only in `cvedexd`, not in CVE Services.

## Add a submitter

A CNA user creates the submitter and its first token:

```console
$ cvedex submitter add bob
Created submitter bob (ID 1)
New user token:
  cvedexd_q3Jx...
It is shown once. Store it now.
```

Send Bob the token, the server URL and your CNA short name.

!!! warning "The token is shown once"
    `cvedexd` stores only its SHA-256. If it is lost, issue a new one with `cvedex submitter token 1`.

## Log in as a submitter

Bob logs in with his name as the username and the token as the API key:

```console
$ cvedex login --url https://cve.acme.org
...
Logged in to https://cve.acme.org as bob (acme, submitter).
```

```console
$ cvedex status
Server     ● https://cve.acme.org  cvedexd 0.1.0
User       bob  submitter
```

## Reserve an ID

The same command as against MITRE:

```console
$ cvedex reserve
Reserved 1 CVE ID
  CVE-2026-1102
Publish with cvedex publish CVE-2026-1102 record.json
```

`cvedexd` reserves it at MITRE for your CNA, so it is a real CVE ID. Bob sees only the IDs he reserved.

## Send a record for review

[Write the record](../records.md#write-the-record), then publish it:

```console
$ cvedex publish CVE-2026-1102 record.json
Sent CVE-2026-1102 for review
```

Nothing reaches MITRE. The record waits for a CNA user to [review it](review.md).

```console
$ cvedex list
CVE ID          STATE                  RESERVED     BY
CVE-2026-1102   RESERVED (in_review)   2026-10-22   bob
```

The TUI works too: press ++e++ on the ID, write the record, save.

## When a reviewer asks for changes

The ID goes back to reserved, with the reviewer's note:

```console
$ cvedex list
CVE ID          STATE                          RESERVED     BY
CVE-2026-1102   RESERVED (changes requested)   2026-10-22   bob

Changes requested
CVE-2026-1102: Add the CWE.
```

Fix the record and send it again with `cvedex publish`. The note clears.

## What a submitter cannot do

Anything else answers `403`: publishing at MITRE, rejecting, updating published records, managing the org. A submitter also cannot see other submitters' IDs.

## Agent tokens

A submitter can give an AI agent its own token. Its writes wait as proposals until the submitter approves them:

```sh
cvedex submitter token 1 --agent
```

See [AI agents](../agents.md#give-the-agent-its-own-token).
