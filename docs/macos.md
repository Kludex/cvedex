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
| Sidebar | Browse your CVE IDs, filtered by state |
| <kbd>+</kbd> in the toolbar | Reserve an ID for this year |
| A record | Read its title, description, affected versions, weaknesses and references |
| **Write Record** or **Edit Record** | Edit the CNA container as JSON, publish or update it |
| **Reject** | Reject the ID, with a reason |
| Account menu | Log in, log out |

Every write asks first. The dialog names the ID and says it will be public.

## The editor

The editor holds the CNA container as JSON, the same file `cvedex publish` takes. Below it, the [schema check](records.md#checked-before-sending) runs as you type and lists every problem. **Publish** stays off until the record is valid.

Paste a GitHub advisory URL at the top and press **Import** to start from the advisory, as [`cvedex record from-advisory`](records.md#from-a-github-advisory) does.

The editor never turns `"` into a curly quote or `--` into a dash, whatever your system's text settings. Either would break the JSON.

## Login

The first launch asks for your server, CNA short name, username and API key. The key goes to your keychain, under the same entry the `cvedex` command uses, so logging in once covers both.

!!! tip "Submitters log in the same way"
    Pick **cvedexd or another server**, enter your [cvedexd](cvedexd/index.md) URL, and your token as the key.

## How it works

The app runs the `cvedex` bundled inside it with `--json`, for every read and write. The schema check, the advisory import and cvedexd support are the client's, not a second copy, so the app and the command never disagree.

Outside the bundle, as when you run `swift run` in `macos/`, the app uses the first `cvedex` on your `PATH`.
