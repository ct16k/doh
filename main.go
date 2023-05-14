package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"doh/config"
)

func main() {
	ctx := context.Background()
	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)

	conf, err := config.Get()
	if err != nil {
		log.Fatalf("error reading config: %v", err)
	}

	srv, err := NewDoHServer(ctx, conf)
	if err != nil {
		log.Fatalf("error creating server: %v", err)
	}
	if conf.Debug {
		log.Printf("%#v", conf)
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
	log.Println("Exiting...")
}
