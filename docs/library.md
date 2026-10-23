# Go library

The client behind the CLI is a package you can import:

```sh
go get github.com/Kludex/cvedex/cveservices
```

```go title="main.go"
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Kludex/cvedex/cveservices"
)

func main() {
	client := cveservices.New(cveservices.Credentials{
		URL:  cveservices.TestURL,
		Org:  os.Getenv("CVE_API_ORG"),
		User: os.Getenv("CVE_API_USER"),
		Key:  os.Getenv("CVE_API_KEY"),
	})
	ids, err := client.Reserve(context.Background(), cveservices.ReserveOptions{Year: 2026, Count: 2})
	if err != nil {
		log.Fatal(err)
	}
	for _, id := range ids {
		fmt.Println(id.ID, id.State)
	}
}
```

Leave `URL` empty for MITRE production.

## Publish a record

Records are `json.RawMessage`. CVE Services validates them, so the library does not model the schema.

```go title="main.go"
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/Kludex/cvedex/cveservices"
)

func main() {
	client := cveservices.New(cveservices.Credentials{
		URL:  os.Getenv("CVE_API_URL"),
		Org:  os.Getenv("CVE_API_ORG"),
		User: os.Getenv("CVE_API_USER"),
		Key:  os.Getenv("CVE_API_KEY"),
	})
	cna, err := os.ReadFile("record.json")
	if err != nil {
		log.Fatal(err)
	}

	record, err := client.Publish(context.Background(), "CVE-2026-1101", cna)
	var apiErr *cveservices.Error
	var pending *cveservices.PendingApproval
	switch {
	case errors.As(err, &apiErr):
		log.Fatalf("%d %s: %s %s", apiErr.Status, apiErr.Code, apiErr.Message, apiErr.Details)
	case errors.As(err, &pending):
		fmt.Println("Waiting for approval as proposal", pending.ProposalID)
	case err != nil:
		log.Fatal(err)
	case cveservices.InReview(record):
		fmt.Println("Sent for review")
	default:
		fmt.Println(string(record))
	}
}
```

| Result | When |
| --- | --- |
| `*cveservices.Error` | The server answered 300 or more. `Code`, `Message` and `Details` come from its error body. |
| `*cveservices.PendingApproval` | You used a cvedexd [agent token](agents.md#give-the-agent-its-own-token). |
| `InReview(record)` is true | You are a cvedexd [submitter](cvedexd/submitters.md). |
| The record | It is published. |

## What else is there

| Method | Does |
| --- | --- |
| `ListIDs(ctx, IDFilter{...})` | Your CNA's IDs, all pages, by state, year or time |
| `ID`, `SetIDState` | One ID, and moving it between reserved and rejected |
| `Record(ctx, id)` | A CVE record |
| `Publish`, `Update`, `Reject`, `ADP` | Write a record |
| `Org`, `Quota`, `User`, `Users`, `AddUser`, `UpdateUser`, `ResetKey` | Your CNA and its users |
| `Health` | The server, and whether it is cvedexd |
| `Review`, `Approve`, `RequestChanges` | cvedexd review, naming the revision you read |
| `Proposals`, `ApproveProposal`, `DenyProposal` | cvedexd agent proposals |
| `Audit` | The cvedexd audit log, a page at a time |
| `Submitters`, `AddSubmitter`, `SetSubmitterDisabled`, `Tokens`, `NewToken`, `RevokeToken` | cvedexd submitters and their tokens |
| `Do(ctx, method, path, query, body, out)` | Any other endpoint |

!!! note "The key never follows a redirect"
    The client does not follow redirects, so your API key is only ever sent to the URL you gave it.

A `429` is retried after its `Retry-After`, up to a minute, three times at most. Cancel the context to stop waiting.

The full reference is on [pkg.go.dev](https://pkg.go.dev/github.com/Kludex/cvedex/cveservices).
