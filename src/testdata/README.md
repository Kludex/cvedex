`recorded/` holds cassettes from `cveawg-test.mitre.org`, written by `scripts/record-fixtures.mjs`. Each one is a request (method, path, body) and the response it got (status, the `content-type`, `cache-control`, `ratelimit-*` and `retry-after` headers, and the raw body). Zig tests load them with `Upstream.Exchange.cassette`; the server tests import them too.

Read every new cassette before committing it, and replace test-org usernames and emails with placeholders.

The other files are hand-written from the CVE Services OpenAPI spec: `reserve.json` and `list.json` need a CNA account on the test instance to record (`CVE_API_ORG=… CVE_API_USER=… CVE_API_KEY=… scripts/record-fixtures.mjs --writes`), `health_cvedexd.json` is this repo's own server, and `cna_container.json` is an input file.
