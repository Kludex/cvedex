# Reserve and publish

A CVE starts as a reserved ID. It becomes public when you publish its record.

## Reserve IDs

```console
$ cvedex reserve
Reserved 1 CVE ID
  CVE-2026-1101
Publish with cvedex publish CVE-2026-1101 record.json
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--year` | this year | Year of the IDs |
| `-n`, `--count` | `1` | How many IDs |
| `--sequential` | off | Ask for consecutive IDs |

```sh
cvedex reserve --count 3 --sequential
```

## Write the record

Save the CNA container, the part of a [CVE JSON 5](https://github.com/CVEProject/cve-schema) record your CNA writes, as `record.json`:

```json title="record.json"
{
  "title": "Path traversal in widget's file server",
  "descriptions": [
    {
      "lang": "en",
      "value": "widget before 1.4.2 serves files outside its root when a path contains '..'."
    }
  ],
  "affected": [
    {
      "vendor": "acme",
      "product": "widget",
      "versions": [{"version": "0", "lessThan": "1.4.2", "status": "affected", "versionType": "semver"}]
    }
  ],
  "problemTypes": [
    {"descriptions": [{"lang": "en", "type": "CWE", "cweId": "CWE-22", "description": "CWE-22 Path Traversal"}]}
  ],
  "references": [{"url": "https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx"}]
}
```

`descriptions`, `affected` and `references` are required. CVE Services fills in `providerMetadata`.

`cvedex` also accepts the container wrapped as `{"cnaContainer": ...}`, or a full record as `cvedex show --json` prints it.

### From a GitHub advisory

If the vulnerability has a [GitHub repository advisory](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories), start from it:

```sh
cvedex record from-advisory https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx > record.json
```

`cvedex` reads the advisory from GitHub's API and writes the CNA container, the way GitHub's own CNA does:

| Advisory | Record |
| --- | --- |
| Summary | `title`, after the project: "widget has path traversal in its file server" |
| Description | `descriptions` |
| Each package and its vulnerable range | An `affected` entry: owner as vendor, package as product, the range as `version` and `lessThan` |
| CWEs | `problemTypes` |
| CVSS 3.x and 4.0 | `metrics`, with the severity |
| Credits | `credits`, by GitHub login |
| The advisory and the links in its description | `references` |

Published advisories need no token. A draft does: set `GH_TOKEN`, for example to your GitHub CLI's token.

```sh
GH_TOKEN=$(gh auth token) cvedex record from-advisory https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx > record.json
```

!!! warning "Read it before you publish"
    The record is only as good as the advisory. Check the title reads well on its own, the version range is right, and a CWE is there. A range `cvedex` cannot express, such as `> 1.0`, is kept as GitHub wrote it, and needs a hand.

### Checked before sending

`cvedex` checks the record against the [CVE JSON 5 schema](https://github.com/CVEProject/cve-schema) before it sends anything, so a mistake costs you no round trip:

```console
$ cvedex publish CVE-2026-1101 record.json
Error: record.json is not a valid CNA container:
  - /affected/0/versions/0: 'oneOf' failed, none matched
    - maxProperties: got 3, want 2
    - missing property 'versionType'
    - missing properties 'versionType', 'lessThanOrEqual'
  - /problemTypes/0/descriptions/0/cweId: minLength: got 4, want 5
  - /problemTypes/0/descriptions/0/cweId: 'CWE-' does not match pattern '^CWE-[1-9][0-9]*$'
```

Each line is the path of a wrong field and what is wrong with it. A `oneOf` lists what each allowed shape is missing: here, a range needs a `versionType`.

`cvedex` bundles schema v5.2.0, the newest, so it never rejects a record CVE Services would accept. CVE Services still validates on its side, and its errors are shown the same way.

## Publish

```console
$ cvedex publish CVE-2026-1101 record.json
Publish CVE-2026-1101 on https://cveawg.mitre.org? It will be public. Yes
Published CVE-2026-1101

CVE-2026-1101  PUBLISHED
Path traversal in widget's file server
...
```

Use `-` to read the record from stdin:

```sh
cat record.json | cvedex publish CVE-2026-1101 -
```

!!! warning "Publishing is public and permanent"
    On MITRE production, `cvedex` asks before every write. Without a terminal, pass `--yes`. The test instance never asks.

## Update

`update` replaces the whole record of a published ID:

```sh
cvedex show CVE-2026-1101 --json > record.json
$EDITOR record.json
cvedex update CVE-2026-1101 record.json
```

## Reject

Reject an ID you will not use, or a duplicate. An unused reserved ID stays reserved forever otherwise.

```sh
cvedex reject CVE-2026-1101 --reason "Duplicate of CVE-2026-1100."
```

This publishes a rejected record. On a published ID, it replaces the record, and the CVE stays rejected for good.

To reject a reserved ID without publishing anything, use `--id-only`. `unreject` reserves it again:

```console
$ cvedex reject CVE-2026-1101 --id-only
CVE-2026-1101 is REJECTED
Check it with cvedex list --state rejected

$ cvedex unreject CVE-2026-1101
CVE-2026-1101 is RESERVED
Check it with cvedex list --state reserved
```

## Add an ADP container

Organizations with the ADP role, such as CISA, add their own container to records other CNAs published:

```sh
cvedex adp CVE-2026-1100 adp.json
```

The file holds the container, bare or as `{"adpContainer": ...}`. Running it again replaces your container. Without the ADP role, CVE Services answers `ADP_ONLY`.

## List and show

```console
$ cvedex list
CVE ID          STATE       RESERVED     BY
CVE-2026-1099   PUBLISHED   2026-10-22   alice@acme.org
CVE-2026-1100   PUBLISHED   2026-10-22   alice@acme.org
CVE-2026-1101   RESERVED    2026-10-22   alice@acme.org
```

| Flag | Meaning |
| --- | --- |
| `--state` | `reserved`, `published` or `rejected` |
| `--year` | IDs of one year |
| `--reserved-after`, `--reserved-before` | Reserved in a time range |
| `--modified-after`, `--modified-before` | Changed in a time range |

Times are dates, such as `2026-10-01`, or RFC 3339 times, such as `2026-10-01T12:00:00Z`:

```sh
cvedex list --state reserved --reserved-before 2026-01-01
```

```console
$ cvedex show CVE-2026-1100
CVE-2026-1100  PUBLISHED

Assigner   acme
Reserved   2026-10-22
Published  2026-10-22
Updated    2026-10-22

widget before 1.4.2 serves files outside its root when a path contains '..'.

Affected
  acme widget  0 to before 1.4.2

References
  https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx
```

`show` works for any published CVE, not only yours. IDs work without the prefix: `cvedex show 2021-44228`.
