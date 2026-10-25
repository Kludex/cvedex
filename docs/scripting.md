# Scripting and CI

Every command takes `--json`. It prints the API's response, and on error, a JSON body on stderr.

```console
$ cvedex list --json | jq -r '.[] | select(.state == "RESERVED") | .cve_id'
CVE-2026-1101
CVE-2026-1102
```

Errors exit with `1`:

```console
$ cvedex show CVE-2026-1101 --json
{"error":"CVE_RECORD_DNE","message":"The cve record for the cve id does not exist."}
$ echo $?
1
```

An error from CVE Services is its body as is. An error from `cvedex` itself has the same shape:

| `error` | When | `details` |
| --- | --- | --- |
| `INVALID_RECORD` | The record fails the [schema check](records.md#checked-before-sending) | `problems`, one line each |
| `NOT_LOGGED_IN` | There are no credentials | |
| `PENDING_APPROVAL` | An agent token's write waits for its submitter | `proposal_id` |
| `CVEDEX_ERROR` | Anything else, such as a missing file | |

Text output is colored on a terminal only, so piping it is safe too.

## Check records in CI

`cvedex record check` runs the schema check alone, with no credentials and no network:

```sh
for record in records/*.json; do cvedex record check "$record" || exit 1; done
```

## Credentials from the environment

Set the four variables instead of running `cvedex login`:

```yaml title=".github/workflows/publish.yml"
name: publish

on:
  workflow_dispatch:
    inputs:
      cve_id:
        required: true

jobs:
  publish:
    runs-on: ubuntu-latest
    env:
      CVE_API_URL: https://cveawg.mitre.org
      CVE_API_ORG: acme
      CVE_API_USER: ${{ secrets.CVE_API_USER }}
      CVE_API_KEY: ${{ secrets.CVE_API_KEY }}
    steps:
      - uses: actions/checkout@v5
      - run: curl -fsSL https://raw.githubusercontent.com/Kludex/cvedex/main/install.sh | sh
      - run: ~/.local/bin/cvedex publish "${{ inputs.cve_id }}" "records/${{ inputs.cve_id }}.json" --yes
```

## Confirmation without a terminal

Writes to MITRE production and `org reset-key` ask first. Without a terminal there is no one to ask, so they fail unless you pass `--yes`:

```console
$ cvedex publish CVE-2026-1101 record.json < /dev/null
Error: publish needs --yes when there is no terminal to ask
```

This way a script never publishes by accident. It does it because you wrote `--yes`.
