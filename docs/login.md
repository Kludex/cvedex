# Log in

```sh
cvedex login
```

In a terminal, `cvedex` asks for:

- **The server**: MITRE production, MITRE's test instance, or another URL, such as a [cvedexd](cvedexd/index.md) server.
- **Your CNA short name**, such as `acme`.
- **Your username**, usually your email.
- **Your API key.**

It checks them against the server, then saves them to `~/.config/cvedex/config.json`, readable by you only.

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

## Rate limits

When CVE Services answers `429 Too Many Requests`, `cvedex` waits as long as its `Retry-After` header says, up to a minute, and tries again, three times at most.

!!! note "Production is the default"
    With no config and no `CVE_API_URL`, `cvedex` talks to MITRE production, `https://cveawg.mitre.org`.
