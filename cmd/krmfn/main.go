package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	krmfnsealedsecretfrom1password "github.com/DWSR/krmfn-sealedsecret-from-1password"
	"github.com/DWSR/krmfn-sealedsecret-from-1password/internal/log"
)

func main() {
	log.Setup()
	log.SetDefaultLevel(slog.LevelInfo)

	// set a 1 minute timeout because a couple of lookups should never take that long
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)

	cmd := krmfnsealedsecretfrom1password.NewCmd(krmfnsealedsecretfrom1password.WithContext(ctx))
	if err := cmd.ExecuteContext(ctx); err != nil {
		slog.ErrorContext(context.Background(), "error executing command", "err", err.Error())
		cancel()
		os.Exit(1)
	}

	cancel()
}
