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

!!! info "CVE Services validates the record"
    `cvedex` sends the JSON as is. If it breaks the schema, you get CVE Services' errors, with the path of each wrong field.

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

## List and show

```console
$ cvedex list
CVE ID          STATE       RESERVED     BY
CVE-2026-1099   PUBLISHED   2026-10-22   alice@acme.org
CVE-2026-1100   PUBLISHED   2026-10-22   alice@acme.org
CVE-2026-1101   RESERVED    2026-10-22   alice@acme.org
```

Filter with `--state reserved`, `published` or `rejected`.

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
