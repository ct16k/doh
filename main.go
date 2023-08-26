package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"doh/config"
)

var startProfiling, stopProfiling func()

func main() {
	conf, err := config.Get()
	if err != nil {
		slog.Error("reading config", "error", err)
		return
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.Level(conf.LogLevel),
	}))
	slog.SetDefault(logger)

	if startProfiling != nil {
		startProfiling()
	}

	srv, err := NewDoHServer(ctx, conf, logger)
	if err != nil {
		logger.Error("error creating server", "error", err)
		return
	}
	logger.Debug("running with config", "conf", conf)

	srv.Start()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	select {
	case <-signalChan:
		srv.Stop()
	case <-ctx.Done():
	}

	signal.Stop(signalChan)
	logger.Info("Exiting...")

	if stopProfiling != nil {
		stopProfiling()
	}
}
