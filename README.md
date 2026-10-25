# cvedex

**Reserve CVE IDs and publish CVE records from your terminal, your scripts, or your AI agent.**

---

`cvedex` is a client for [CVE Services](https://www.cve.org/AllResources/CveServices), the API every CNA uses to reserve CVE IDs and publish CVE records.

The key features are:

- **One binary**: a CLI, a terminal UI and a Go library. No runtime to install.
- **Safe by default**: it asks before anything public happens, and your API key lives in your system keychain.
- **Made for scripts**: every command has `--json`, and `--yes` skips the questions.
- **Made for agents**: `cvedexd` serves the same tools over remote MCP, and an agent's writes wait for your approval.
- **Shareable**: with `cvedexd`, your maintainers reserve IDs and propose records, and only your CNA's users publish.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Kludex/cvedex/main/install.sh | sh
```

The script checks the checksum of what it downloads, and if you have `gh`, that GitHub built it.

On Windows, download the `.zip` from the [releases page](https://github.com/Kludex/cvedex/releases).

## Example

Log in to MITRE's test instance, where nothing you publish is real:

```sh
cvedex login --test
```

Reserve an ID:

```console
$ cvedex reserve
Reserved 1 CVE ID
  CVE-2026-1101
Publish with cvedex publish CVE-2026-1101 record.json
```

Write `record.json`:

```json
{
  "title": "Path traversal in widget's file server",
  "descriptions": [{"lang": "en", "value": "widget before 1.4.2 serves files outside its root."}],
  "affected": [
    {
      "vendor": "acme",
      "product": "widget",
      "versions": [{"version": "0", "lessThan": "1.4.2", "status": "affected", "versionType": "semver"}]
    }
  ],
  "references": [{"url": "https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx"}]
}
```

Already have a GitHub advisory? Let `cvedex` write it for you:

```sh
cvedex record from-advisory https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx > record.json
```

And publish it. `cvedex` checks it against the CVE schema first:

```console
$ cvedex publish CVE-2026-1101 record.json
Published CVE-2026-1101

CVE-2026-1101  PUBLISHED
Path traversal in widget's file server
...
```

That's it. On production, `cvedex` asks before publishing, since the record becomes public. Prefer to click around? Run `cvedex tui`, or build the [macOS app](docs/macos.md) with `macos/build.sh`.

## cvedexd

CVE Services has no "reserve only" permission. Anyone who can reserve an ID can also publish.

`cvedexd` fixes that. It's a small server you deploy to Cloudflare Workers, in front of CVE Services:

- **Maintainers** get their own tokens. They reserve IDs and send records for review.
- **Your CNA's users** review each record, with a diff, and approve or ask for changes.
- **CVE Services** only sees requests your CNA approved.

It speaks the same API, so `cvedex` works with it as is.

## Learn more

- [Log in](docs/login.md)
- [Write and publish records](docs/records.md)
- [The terminal UI](docs/tui.md)
- [The macOS app](docs/macos.md)
- [AI agents](docs/agents.md)
- [The Go library](docs/library.md)
- [cvedexd](docs/cvedexd/index.md)

## License

This project is licensed under the terms of the [MIT license](LICENSE).
