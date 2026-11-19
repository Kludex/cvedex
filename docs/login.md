# Log in

```sh
cvedex login
```

In a terminal, `cvedex` asks for:

- **The server**: MITRE production, MITRE's test instance, or another URL, such as a [cvedexd](cvedexd/index.md) server.
- **Your CNA short name**, such as `acme`.
- **Your username**, usually your email.
- **Your API key.**

It checks them against the server, then saves them:

- **The API key** goes in your system keychain: the macOS Keychain, the Secret Service on Linux (GNOME Keyring or KWallet), or the Windows Credential Manager.
- **The rest** goes in `~/.config/cvedex/config.json`, readable by you only.

!!! info "No keychain, such as on a server"
    If there is no keychain to use, `login` says so and puts the key in `config.json` too. On a server, you may prefer the [environment variables](#environment-variables).

Run `cvedex status` to see where you are logged in:

```console
$ cvedex status
Server     ● https://cveawg-test.mitre.org  CVE Services
User       alice@acme.org ADMIN
CNA        Acme (acme)
```

## Start on the test instance

```sh
cvedex login --test
```

`--test` skips the server question and uses `https://cveawg-test.mitre.org`. Records you publish there are not public.

!!! tip "Ask MITRE for a test account"
    The test instance has its own accounts. Your production key does not work there.

## Without a terminal

Pass `--org` and `--user`, and pipe the API key on stdin:

```sh
echo "$CVE_API_KEY" | cvedex login --test --org acme --user alice@acme.org
```

!!! warning "Keep the key out of your shell history"
    `--key` exists, but anything you type as an argument ends up in your shell history and in `ps`. Prefer the prompt or stdin.

## Only over https

`cvedex` refuses a server URL that starts with `http://`, because every request carries your API key:

```console
$ cvedex --url http://cve.acme.org status
Error: http://cve.acme.org would send your API key unencrypted; use https://
```

`http://localhost` and loopback addresses such as `http://127.0.0.1:8787` are allowed, for a [local cvedexd](cvedexd/deploy.md#run-it-locally).

## Use a GitHub repository

```sh
cvedex login --url https://github.com/acme/cves
```

A URL of a repository on `github.com` asks for nothing: `cvedex` signs in with your GitHub login. See [GitHub repository](github.md).

## Several accounts

Each `cvedex login` adds an account and uses it. The ones you logged in to before stay:

```console
$ cvedex accounts
#   SERVER                            USER                 ORG
1   https://cveawg-test.mitre.org     alice@acme.org       acme
2   https://cveawg.mitre.org          alice@acme.org       acme   in use
3   https://github.com/acme/cves      alice                acme
Use another with cvedex accounts switch <#>

$ cvedex accounts switch 1
Now using https://cveawg-test.mitre.org as alice@acme.org.
```

An account is a username on a server. Logging in to it again replaces its key.

!!! tip "Check before you publish"
    `cvedex status` says which account a command will use. Writes to MITRE production ask first either way.

## Use another server for one command

`--url` overrides the saved server for a single command:

```sh
cvedex --url https://cveawg-test.mitre.org list
```

## Environment variables

These override the saved config, one by one:

| Variable | Meaning |
| --- | --- |
| `CVE_API_URL` | Server URL |
| `CVE_API_ORG` | CNA short name |
| `CVE_API_USER` | Username |
| `CVE_API_KEY` | API key |

They are the names [`cvelib`](https://github.com/RedHatProductSecurity/cvelib) uses, so an existing setup works as is.

## Log out

```console
$ cvedex logout
Logged out of https://cveawg-test.mitre.org as alice@acme.org.
```

`logout` forgets the account in use and deletes its API key from your keychain. If you are logged in to others, `cvedex` says which one it uses next:

```console
$ cvedex logout
Logged out of https://cveawg-test.mitre.org as alice@acme.org.
Now using https://cveawg.mitre.org as alice@acme.org.
```

!!! note "Environment variables still apply"
    `logout` only forgets what `login` saved. If `CVE_API_*` variables are set, `cvedex` keeps using them.

## Rate limits

When CVE Services answers `429 Too Many Requests`, `cvedex` waits as long as its `Retry-After` header says, up to a minute, and tries again, three times at most.

!!! note "Production is the default"
    With no config and no `CVE_API_URL`, `cvedex` talks to MITRE production, `https://cveawg.mitre.org`.
