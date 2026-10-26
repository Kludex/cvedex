# macOS app

`cvedex.app` is a native window over the same CVE IDs and records as the [terminal UI](tui.md).

```sh
git clone https://github.com/Kludex/cvedex
cd cvedex
macos/build.sh
open macos/build/cvedex.app
```

`build.sh` needs Xcode 16 or later and Go. It builds the app and a universal `cvedex` next to it, for Apple silicon and Intel, and signs both ad hoc.

!!! info "Not notarized yet"
    You build the app on your Mac, so macOS opens it without asking. A copy downloaded from elsewhere would need notarization, which a release does not do yet.

## What it does

| Where | What you do |
| --- | --- |
| Sidebar | Browse your CVE IDs by state, or search them |
| <kbd>+</kbd> in the toolbar | Reserve an ID for this year. Its menu also has **New from GitHub Advisory**. |
| An ID | Read its record: description, affected versions, severity, weaknesses, references and credits |
| **Write Record** or **Edit Record** | Build the record in a form, or edit it as JSON, then publish or update it |
| **More** > **Reject** | Reject the ID, with a reason |
| The foot of the sidebar | See who you are logged in as and where, switch account, log out |

Every write asks first. The dialog names the ID and says it will be public.

## The builder

**Write Record** opens a form with a section for each part of the record:

| Section | What you fill in |
| --- | --- |
| Summary and Description | A title, and what an attacker can do. The description takes Markdown. |
| Affected product | Vendor, product, repository, package registry, and the versions, such as *affected from 0 before 1.2.3* |
| Weaknesses | CWE IDs, picked from MITRE's list by number or by name |
| Severity | A CVSS 3.1 score. Pick each metric, and the app computes the vector and the score. |
| References | Links, each tagged as an advisory, a patch, release notes and so on |
| Credits | Who found, reported or fixed it |

The status bar runs the [schema check](records.md#checked-before-sending) as you type. Click its problem count to list the problems and mark each field that has one. **Publish** stays off until the record is valid.

**JSON** in the toolbar shows the same record as the CNA container, the file `cvedex publish` takes. Edits in either view show up in the other. Fields the form has no control for stay as they are.

### From a GitHub advisory

A repository security advisory already has most of a record, so you can start from one, as [`cvedex record from-advisory`](records.md#from-a-github-advisory) does:

| Where | What happens |
| --- | --- |
| **+** > **New from GitHub Advisory** | Reserves an ID for this year and opens its builder, filled in from the advisory |
| **Import Advisory** on an ID with no record | Fills in that ID's record |
| The import button in the editor's toolbar | Replaces the record you are editing |

The app fetches the advisory before it reserves anything, so a wrong URL costs no ID. Check what it filled in, add what GitHub does not know, and publish.

!!! info "Draft advisories need a GitHub token"
    GitHub only shows a draft advisory to its repository's maintainers. Open the app from a terminal with `open --env GH_TOKEN="$(gh auth token)" macos/build/cvedex.app` to import one.

### Drafts

Every change is saved as a draft on your Mac, per ID. Close the editor, or quit the app, and the draft is there next time. The sidebar marks IDs with an unsent draft with a pencil. Publishing removes the draft, and so does **Discard**.

!!! info "The JSON view is plain text"
    It never turns `"` into a curly quote or `--` into a dash, whatever your system's text settings. Either would break the JSON.

## Login

The first launch asks for your server, CNA short name, username and API key. The key goes to your keychain, under the same entry the `cvedex` command uses, so logging in once covers both.

!!! tip "Submitters log in the same way"
    Pick **cvedexd or another server**, enter your [cvedexd](cvedexd/index.md) URL, and your token as the key.

## How it works

The app runs the `cvedex` bundled inside it with `--json`, for every read and write. The schema check, the advisory import and cvedexd support are the client's, not a second copy, so the app and the command never disagree.

Outside the bundle, as when you run `swift run` in `macos/`, the app uses the first `cvedex` on your `PATH`.
