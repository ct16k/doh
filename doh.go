package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"doh/domain"
	"doh/gateways"
	"encoding/base64"
	"fmt"
	"golang.org/x/sync/semaphore"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"strconv"
)

type HTTPServer struct {
	server   http.Server
	certFile string
	keyFile  string
}

type DoHServer struct {
	ctx           context.Context
	config        *domain.DoHConfig
	servers       []HTTPServer
	httpSemaphore *semaphore.Weighted
	dnsClient     *gateways.DNSClient
}

func NewDoHServer(ctx context.Context) *DoHServer {
	config := ctx.Value("config").(*domain.DoHConfig)
	dohServer := &DoHServer{
		ctx:           ctx,
		config:        config,
		httpSemaphore: semaphore.NewWeighted(config.HTTPWorkers),
		dnsClient:     gateways.NewDNSClient(ctx),
	}

	for _, listenAddr := range config.ListenAddrs {
		server := http.Server{
			Addr: listenAddr.Addr,
		}
		if listenAddr.ClientCAs != "" {
			caCerts, err := ioutil.ReadFile(listenAddr.ClientCAs)
			if err != nil {
				log.Fatalf("could not read client CAs: %v", err)
			}
			caCertPool := x509.NewCertPool()
			ok := caCertPool.AppendCertsFromPEM(caCerts)
			if !ok {
				log.Fatalf("could not load CA certs from %s",
					listenAddr.ClientCAs)
			}

			tlsConfig := &tls.Config{
				ClientCAs:  caCertPool,
				ClientAuth: tls.RequireAndVerifyClientCert,
			}
			tlsConfig.BuildNameToCertificate()

			server.TLSConfig = tlsConfig
			if config.Debug {
				log.Printf("%#v", *tlsConfig)
			}
		}

		dohServer.servers = append(dohServer.servers, HTTPServer{
			server:   server,
			certFile: listenAddr.CertFile,
			keyFile:  listenAddr.KeyFile,
		})
	}

	return dohServer
}

func (s *DoHServer) Start() {
	s.dnsClient.Start()

	http.HandleFunc("/", s.requestHandler)
	for _, srv := range s.servers {
		log.Printf("Starting %s server...\n", srv.server.Addr)
		go func(srv HTTPServer) {
			var err error
			if srv.certFile == "" {
				err = srv.server.ListenAndServe()
			} else {
				err = srv.server.ListenAndServeTLS(srv.certFile, srv.keyFile)
			}
			if err != http.ErrServerClosed {
				log.Fatalf("error starting server %s: %v", srv.server.Addr, err)
			}
		}(srv)
	}

	log.Println("Started.")
}

func (s *DoHServer) Stop() {
	for _, srv := range s.servers {
		log.Printf("Stopping %s server...\n", srv.server.Addr)
		srv.server.Shutdown(s.ctx)
	}
	log.Println("Stopped.")

	s.dnsClient.Stop()
}

func (s *DoHServer) requestHandler(w http.ResponseWriter, r *http.Request) {
	s.httpSemaphore.Acquire(s.ctx, 1)
	defer s.httpSemaphore.Release(1)

	if s.config.Debug {
		log.Printf("%#v", r)
	}
	contentType := r.Header.Get("Accept")
	if (contentType != "") && (contentType != "application/dns-message") {
		http.Error(w, "unknown MIME type", http.StatusBadRequest)
		return
	}

	var body []byte
	var err error
	if r.Method == "GET" {
		query, ok := r.URL.Query()["dns"]
		if ok && (len(query) == 1) {
			body, err = base64.RawURLEncoding.DecodeString(query[0])
		} else {
			err = fmt.Errorf("bad request")
		}
	} else if r.Method == "POST" {
		contentType = r.Header.Get("Content-Type")
		if (contentType != "") && (contentType != "application/dns-message") {
			err = fmt.Errorf("unknown body MIME type")
		} else {
			body, err = ioutil.ReadAll(r.Body)
			if err == nil {
				bodyLen := len(body)
				if bodyLen == 0 {
					err = fmt.Errorf("empty body")
				} else {
					contentLengthStr := r.Header.Get("Content-Length")
					if contentLengthStr != "" {
						var contentLength int
						contentLength, err = strconv.Atoi(contentLengthStr)
						if err != nil {
							err = fmt.Errorf("invalid body length")
						} else if contentLength != bodyLen {
							err = fmt.Errorf("mismatched body size")
						}
					}
				}
			}
		}
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := s.dnsClient.QueryDNS(body)
	if err != nil {
		log.Printf("error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respHeaders := w.Header()
	respHeaders.Set("Content-Type", "application/dns-message")
	if resp.TTL != math.MaxUint32 {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", resp.TTL))
	}

	msgLen := len(resp.Msg)
	respHeaders.Set("Content-Length", strconv.Itoa(msgLen))
	n, err := w.Write(resp.Msg)
	if err != nil {
		log.Printf("could not reply: %v", err)
	} else if n != msgLen {
		log.Printf("incomplete response sent (%d/%d)", n, msgLen)
	}
}
