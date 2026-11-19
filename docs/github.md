# GitHub repository

```sh
cvedex login --url https://github.com/acme/cves
```

`cvedex` then works against a GitHub repository instead of a [cvedexd](cvedexd/index.md) server. Maintainers reserve CVE IDs and send records for review, your CNA's admins approve them, and there is nothing to deploy.

## Why

CVE Services has no "reserve only" permission, so you cannot hand its key to every maintainer who needs a CVE ID.

Here the key lives in the repository's GitHub Actions secrets. People and agents hold only their GitHub login, and GitHub decides who may do what.

## How it maps

| In `cvedex` | In the repository |
| --- | --- |
| A reserved ID | A branch, `cve/CVE-2026-1102` |
| A record sent for review | A pull request that adds `records/CVE-2026-1102.json` |
| Request changes | A pull request review that requests changes, with your note |
| Approve | The pull request, squashed and merged |
| Publish | A workflow that runs on the merge, with the CNA's key |
| A CNA admin | Whoever GitHub lets merge into the default branch |

## Set up the repository

### 1. Create a private repository

!!! danger "Keep it private"
    Records hold the details of a vulnerability before they are public. Everyone who can read the repository can read them.

### 2. Store the key in an environment

Create an environment named `cve`, under **Settings** > **Environments**:

| Kind | Name | Value |
| --- | --- | --- |
| Variable | `CVE_API_ORG` | Your CNA short name |
| Secret | `CVE_API_USER` | A CVE Services user of your CNA |
| Secret | `CVE_API_KEY` | Its API key |

Limit its **Deployment branches** to `main`.

!!! danger "An environment secret, limited to `main`"
    Anyone with write access can push a branch with a workflow of their own. A repository secret would be readable from it. An environment limited to `main` is not, so only the workflows your admins merged see the key.

### 3. Add the two workflows

`cvedex reserve` runs the first one. It prints each ID it reserved as a notice, which `cvedex` reads in the run's log:

```yaml title=".github/workflows/cvedex-reserve.yml"
name: cvedex-reserve

on:
  workflow_dispatch:
    inputs:
      year:
        required: true
      count:
        default: "1"
      sequential:
        default: "false"

permissions: {}

jobs:
  reserve:
    runs-on: ubuntu-latest
    environment: cve
    env:
      CVE_API_URL: https://cveawg.mitre.org
      CVE_API_ORG: ${{ vars.CVE_API_ORG }}
      CVE_API_USER: ${{ secrets.CVE_API_USER }}
      CVE_API_KEY: ${{ secrets.CVE_API_KEY }}
      YEAR: ${{ inputs.year }}
      COUNT: ${{ inputs.count }}
      SEQUENTIAL: ${{ inputs.sequential }}
    steps:
      - run: curl -fsSL https://raw.githubusercontent.com/Kludex/cvedex/main/install.sh | sh
      - run: |
          ~/.local/bin/cvedex reserve --json --year "$YEAR" --count "$COUNT" --sequential="$SEQUENTIAL" > ids.json
          jq -r '.[] | "::notice title=cvedex::\(.cve_id)"' ids.json
```

The second one publishes the records a merge added or changed:

```yaml title=".github/workflows/cvedex-publish.yml"
name: cvedex-publish

on:
  push:
    branches: [main]
    paths: ["records/**"]

permissions:
  contents: read

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: cve
    env:
      CVE_API_URL: https://cveawg.mitre.org
      CVE_API_ORG: ${{ vars.CVE_API_ORG }}
      CVE_API_USER: ${{ secrets.CVE_API_USER }}
      CVE_API_KEY: ${{ secrets.CVE_API_KEY }}
      BEFORE: ${{ github.event.before }}
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
          persist-credentials: false
      - run: curl -fsSL https://raw.githubusercontent.com/Kludex/cvedex/main/install.sh | sh
      - shell: bash
        run: |
          git diff --name-only --diff-filter=AM "$BEFORE" "$GITHUB_SHA" -- 'records/CVE-*.json' | while read -r file; do
            id=$(basename "$file" .json)
            if ~/.local/bin/cvedex show "$id" > /dev/null 2>&1; then verb=update; else verb=publish; fi
            ~/.local/bin/cvedex "$verb" "$id" "$file" --yes
          done
```

!!! info "The file names matter"
    `cvedex` looks for `cvedex-reserve.yml` and `cvedex-publish.yml`, and for records in `records/`.

!!! tip "Try it on the test instance first"
    Set `CVE_API_URL` to `https://cveawg-test.mitre.org` in both workflows, with a test account's key.

### 4. Say who the admins are

Name them in `CODEOWNERS`, by team or by user:

```text title=".github/CODEOWNERS"
* @acme/cve-admins
```

Then add a rule for `main`, under **Settings** > **Rules**:

- **Require a pull request before merging**, with one approval and **Require review from Code Owners**.
- No bypass, for repository administrators either.

Everyone else gets write access. They can reserve IDs and open pull requests, and GitHub refuses their merges.

!!! warning "Without the rule, anyone with write access publishes"
    `cvedex` asks GitHub to merge, and GitHub is what says no. The rule also covers `.github/`, so nobody changes the workflows without an admin.

`cvedex` merges with a squash, which GitHub allows by default.

## Log in

```console
$ cvedex login --url https://github.com/acme/cves
Logged in to https://github.com/acme/cves as alice (acme, admin).
```

`cvedex` uses `GH_TOKEN` or `GITHUB_TOKEN`, else the [GitHub CLI](https://cli.github.com)'s login, from `gh auth login`. It saves the URL and your GitHub name, and no token.

In the [macOS app](macos.md), pick **GitHub repository** as the server and type the repository, such as `acme/cves`.

```console
$ cvedex status
Server     ● https://github.com/acme/cves  cvedexd on GitHub
User       alice admin
```

## Reserve an ID

```console
$ cvedex reserve
Reserved 1 CVE ID
  CVE-2026-1102
Publish with cvedex publish CVE-2026-1102 record.json
```

`cvedex` starts the reserve workflow, waits for it, which takes about half a minute, and creates the ID's branch.

## Send a record for review

[Write the record](records.md#write-the-record), then publish it:

```console
$ cvedex publish CVE-2026-1102 record.json
Sent CVE-2026-1102 for review
```

Nothing reaches MITRE. `cvedex` commits the record to the ID's branch and opens a pull request. Send it again to change it.

`cvedex update` does the same for an ID that is published already.

```console
$ cvedex list
CVE ID          STATE                  RESERVED     BY
CVE-2026-1100   PUBLISHED              2026-10-20   bob
CVE-2026-1102   RESERVED (in_review)   2026-10-22   bob
CVE-2026-1103   RESERVED (reserved)
```

!!! note "The list is what the repository holds"
    `RESERVED` is the day the ID's first pull request was opened, and `BY` who opened it. Both are empty until there is one.

## Review

The [review commands](cvedexd/review.md) work as they do on `cvedexd`:

```console
$ cvedex review
CVE ID          ACTION    REV   SUBMITTER   SENT         TITLE
CVE-2026-1102   publish   2     bob         2026-10-22   Path traversal in widget's file server

$ cvedex review show CVE-2026-1102
...
Approve with cvedex review approve CVE-2026-1102 --revision 2

$ cvedex review approve CVE-2026-1102 --revision 2
Approved CVE-2026-1102
```

`REV` is the number of commits in the pull request. If the submitter pushes while you read, approving fails with `STALE_REVISION` and nothing is merged.

`approve` approves the pull request, merges it, and waits for the publish workflow.

!!! warning "A merge whose workflow fails is not published"
    `approve` then fails with a link to the run. The record is merged, so fix the cause and run the workflow again on GitHub.

`cvedex review request-changes CVE-2026-1102 "Add the CWE." --revision 2` leaves a review that requests changes. The submitter sees the note in `cvedex list` until they send the record again.

You can also review the pull request on GitHub. `cvedex` shows the same state.

In the [macOS app](macos.md), an ID that waits for a review has **Approve** and **Request Changes** above its record.

## See what happened

```console
$ cvedex audit
TIME                  ACTOR   AS                  REQUEST                                                  STATUS
2026-10-22 11:05:00   alice   push                cvedex-publish CVE-2026-1102: Path traversal in widget   200
2026-10-22 10:00:00   bob     workflow_dispatch   cvedex-reserve cvedex-reserve                            200
```

Every write to CVE Services is a workflow run, and `audit` lists them: who started it, and `200` for a run that worked or `500` for one that failed. The pull requests and the history of `main` have the rest.

## AI agents

Give the agent `cvedex` and a GitHub token of an account that is not an admin. Its records are pull requests, and they wait for an admin like anyone else's.

A fine-grained token needs these permissions on the repository:

| Permission | Access | For |
| --- | --- | --- |
| Contents | Read and write | Branches and records |
| Pull requests | Read and write | Sending records for review |
| Actions | Read and write | Starting the reserve workflow, and reading the IDs it reserved |

!!! info "No MCP server"
    The [MCP server](agents.md) is part of `cvedexd`. Against a repository, the agent runs the `cvedex` commands, with `--json`.

## What it does not do

| | Instead |
| --- | --- |
| `reject`, `unreject`, `adp` and the `org` commands | Use them against CVE Services itself, with a CNA user's key |
| `proposals` and `submitter` | GitHub's permissions and pull requests take their place |
| `list` filtered by time | Filter by `--state` and `--year` |
| GitHub Enterprise Server | Only `github.com` |
