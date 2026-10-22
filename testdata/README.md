`recorded/` holds cassettes from `cveawg-test.mitre.org`, written by `scripts/record-fixtures.mjs`. Each one is a request (method, path, body) and the response it got (status, the `content-type`, `cache-control`, `ratelimit-*` and `retry-after` headers, and the raw body). Go tests replay them with `internal/cassette`; the server tests import them too.

Without credentials the script records only the public and error responses. The authenticated ones need a CNA account on the test instance, and `--writes` reserves an ID and publishes a test record to it:

```sh
CVE_API_ORG=... CVE_API_USER=... CVE_API_KEY=... scripts/record-fixtures.mjs --writes
```

The script replaces the account's org name, short name, UUIDs, username and real name with `acme` / `alice@acme.test` placeholders, and writes nothing if any of them or the key is still in a cassette. Read every new cassette before committing it anyway.
