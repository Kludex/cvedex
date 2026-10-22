// Command cvedex reserves CVE IDs and publishes CVE records through CVE Services.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/Kludex/cvedex/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Main(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
