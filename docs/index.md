# cvedex

`cvedex` is a client for [CVE Services](https://www.cve.org/AllResources/CveServices), the API CNAs use to reserve CVE IDs and publish CVE records.

It is one static binary with a CLI, a terminal UI, an MCP server for AI agents, and a Go library.

```console
$ cvedex reserve
Reserved 1 CVE ID
  CVE-2026-1101
Publish with cvedex publish CVE-2026-1101 record.json

$ cvedex publish CVE-2026-1101 record.json
Publish CVE-2026-1101 on https://cveawg.mitre.org? It will be public. Yes
Published CVE-2026-1101

CVE-2026-1101  PUBLISHED
Path traversal in widget's file server
...
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Kludex/cvedex/main/install.sh | sh
```

The script downloads the latest release for your OS and architecture, checks it against `SHA256SUMS`, and puts `cvedex` in `~/.local/bin`. Set `CVEDEX_INSTALL_DIR` to install somewhere else.

If [`gh`](https://cli.github.com) is installed and logged in, the script also checks that GitHub's release workflow built the archive. Otherwise, check it yourself:

```sh
gh attestation verify cvedex-v0.1.0-aarch64-macos.tar.gz --repo Kludex/cvedex
```

On Windows, download the `.zip` from the [releases page](https://github.com/Kludex/cvedex/releases), check it with the same `gh attestation verify`, and put `cvedex.exe` on your `PATH`.

## First steps

Log in to MITRE's test instance, where nothing you publish is real:

```sh
cvedex login --test
```

Then reserve an ID and look at it:

```console
$ cvedex reserve
Reserved 1 CVE ID
  CVE-2026-1101
Publish with cvedex publish CVE-2026-1101 record.json

$ cvedex list --state reserved
CVE ID          STATE      RESERVED     BY
CVE-2026-1101   RESERVED   2026-10-22   alice@acme.org
```

Next, [write and publish its record](records.md).

## cvedexd

CVE Services has no "reserve only" permission. Anyone who can reserve an ID can also publish.

[`cvedexd`](cvedexd/index.md) is a small server you put between your people and CVE Services. Maintainers reserve IDs and send records for review, and only your CNA's users publish them. It speaks the same API, so `cvedex` works against it unchanged.
