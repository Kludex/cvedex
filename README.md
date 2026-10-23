# cvedex

`cvedex` is a client for [CVE Services](https://www.cve.org/AllResources/CveServices), the API CNAs use to reserve CVE IDs and publish CVE records. It is one static binary with a CLI, a terminal UI, an MCP server for AI agents, and a Go library.

`cvedexd` is a small server you put between your people and CVE Services, so maintainers can reserve IDs and send records for review without being able to publish.

```console
$ cvedex reserve
Reserved 1 CVE ID
  CVE-2026-1101
Publish with cvedex publish CVE-2026-1101 record.json

$ cvedex publish CVE-2026-1101 record.json
Publish CVE-2026-1101 on https://cveawg.mitre.org? It will be public. Yes
Published CVE-2026-1101
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Kludex/cvedex/main/install.sh | sh
```

The script picks the release for your OS and architecture, checks its checksum, and, if `gh` is logged in, its build provenance. On Windows, download the `.zip` from the [releases page](https://github.com/Kludex/cvedex/releases).

## Quick start

Log in to MITRE's test instance, where nothing you publish is real. The API key goes in your system keychain:

```sh
cvedex login --test
```

Then reserve an ID, or open the terminal UI:

```sh
cvedex reserve
cvedex tui
```

## Why cvedexd

CVE Services has no "reserve only" permission. Anyone who can reserve an ID can also publish. `cvedexd` runs on Cloudflare Workers with D1, speaks the same API, and holds publishing until one of your CNA's users approves it. `cvedex` works against it unchanged.

## Documentation

- [Log in](docs/login.md)
- [Write and publish records](docs/records.md)
- [Terminal UI](docs/tui.md)
- [AI agents over MCP](docs/agents.md)
- [Go library](docs/library.md)
- [cvedexd](docs/cvedexd/index.md)

## License

[MIT](LICENSE)
