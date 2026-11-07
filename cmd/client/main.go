// Command gophkeeper is the GophKeeper command line client.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/magicelemental11/gophkeeper/internal/client/cli"
	"github.com/magicelemental11/gophkeeper/internal/vault"
)

func main() {
	vault.RegisterTypes()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Execute(ctx, cli.NewRoot(cli.DefaultDeps()), os.Args[1:])
	stop()
	os.Exit(code)
}
