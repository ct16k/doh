package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"doh/domain"
)

func main() {
	ctx := context.Background()
	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)

	conf, err := domain.GetConfig()
	if err != nil {
		log.Fatalf("error reading config: %v", err)
	}
	ctx = context.WithValue(ctx, domain.ContextKey("config"), conf)

	srv := NewDoHServer(ctx)
	if conf.Debug {
		log.Printf("%#v", *conf)
		log.Printf("%#v", *srv)
	}

	srv.Start()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	select {
	case <-signalChan:
		srv.Stop()
	case <-ctx.Done():
	}

	signal.Stop(signalChan)
}
