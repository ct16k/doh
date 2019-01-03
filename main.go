package main

import (
	"context"
	"doh/domain"
	"log"
	"os"
	"os/signal"
)

func main() {
	ctx := context.Background()
	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)

	conf, err := domain.GetConfig()
	if err != nil {
		log.Fatalf("error reading config: %v", err)
	}
	ctx = context.WithValue(ctx, "config", conf)

	srv := NewDoHServer(ctx)
	if conf.Debug {
		log.Printf("%#v", *conf)
		log.Printf("%#v", *srv)
	}

	srv.Start()

	signalChan := make(chan os.Signal)
	signal.Notify(signalChan, os.Interrupt)
	select {
	case <-signalChan:
		srv.Stop()
	case <-ctx.Done():
	}

	signal.Stop(signalChan)
}
