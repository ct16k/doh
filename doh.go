package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"doh/config"
	"doh/dns"

	"golang.org/x/sync/semaphore"
)

type HTTPServer struct {
	server   *http.Server
	certFile string
	keyFile  string
}

type DoHServer struct {
	ctx           context.Context
	conf          *config.DoHServer
	logger        *slog.Logger
	httpSemaphore *semaphore.Weighted
	dnsClient     *dns.Client
	bufPool       sync.Pool
	servers       []HTTPServer
	wgServers     sync.WaitGroup
}

func NewDoHServer(ctx context.Context, conf *config.DoHServer, logger *slog.Logger) (*DoHServer, error) {
	dnsClient, err := dns.NewClient(ctx, conf, logger)
	if err != nil {
		return nil, fmt.Errorf("dns client: %w", err)
	}
	dohServer := &DoHServer{
		ctx:           ctx,
		conf:          conf,
		logger:        logger,
		httpSemaphore: semaphore.NewWeighted(conf.HTTPWorkers),
		dnsClient:     dnsClient,
		bufPool: sync.Pool{
			New: func() any {
				return make([]byte, 1<<16)
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", dohServer.requestHandler)

	for _, listenAddr := range conf.ListenAddrs {
		server := http.Server{
			Addr:    listenAddr.Addr,
			Handler: mux,
		}

		tlsConfig := tls.Config{
			ServerName: listenAddr.Addr,
			MinVersion: tls.VersionTLS12,
		}

		var tlsConfigSet bool
		if listenAddr.ClientCAs != "" {
			caCerts, err := os.ReadFile(listenAddr.ClientCAs)
			if err != nil {
				return nil, fmt.Errorf("could not read client CAs: %w", err)
			}
			caCertPool := x509.NewCertPool()
			ok := caCertPool.AppendCertsFromPEM(caCerts)
			if !ok {
				return nil, fmt.Errorf("could not load CA certs from %s", listenAddr.ClientCAs)
			}

			tlsConfig = tls.Config{
				ClientCAs:  caCertPool,
				ClientAuth: tls.RequireAndVerifyClientCert,
			}
			tlsConfigSet = true
		}

		if strings.HasPrefix(listenAddr.CertFile, "self:") {
			hostname := strings.TrimPrefix(listenAddr.CertFile, "self:")
			if hostname == "" {
				hostname = listenAddr.Addr
			}

			tlsCert, err := dohServer.generateSelfSignedCert(hostname, listenAddr.KeyFile, time.Now(),
				10*365*24*time.Hour)
			if err != nil {
				return nil, fmt.Errorf("generate self-signed cert: %w", err)
			}

			tlsConfig.Certificates = []tls.Certificate{tlsCert}
			tlsConfigSet = true
		}

		if tlsConfigSet {
			server.TLSConfig = &tlsConfig
			logger.Debug("using TLS", "tlsConfig", &tlsConfig)
		}

		dohServer.servers = append(dohServer.servers, HTTPServer{
			server:   &server,
			certFile: listenAddr.CertFile,
			keyFile:  listenAddr.KeyFile,
		})
	}

	return dohServer, nil
}

func (s *DoHServer) Start() {
	s.dnsClient.Start()
	s.logger.Info("DNS client started", "resolvers", s.conf.DNSResolvers)

	for _, srv := range s.servers {
		s.wgServers.Add(1)
		go func(srv HTTPServer) {
			defer s.wgServers.Done()

			logger := s.logger.With("addr", srv.server.Addr)
			var err error
			if srv.certFile == "" {
				logger.Info("Starting HTTP server")
				err = srv.server.ListenAndServe()
			} else if strings.HasPrefix(srv.certFile, "self:") {
				logger.Info("Starting HTTPS self-signed listener")
				err = srv.server.ListenAndServeTLS("", "")
			} else {
				logger.Info("Starting HTTPS listener")
				err = srv.server.ListenAndServeTLS(srv.certFile, srv.keyFile)
			}
			if err != http.ErrServerClosed {
				panic(fmt.Errorf("error starting server %s: %v", srv.server.Addr, err))
			}
		}(srv)
	}

	s.logger.Info("Service started")
}

func (s *DoHServer) Stop() {
	for _, srv := range s.servers {
		logger := s.logger.With("addr", srv.server.Addr)
		logger.Info("Stopping server")
		if err := srv.server.Shutdown(s.ctx); err != nil {
			logger.Error("Stopping server", "error", err)
		}
	}
	s.wgServers.Wait()
	s.logger.Info("Servers stopped")

	if err := s.dnsClient.Stop(); err != nil {
		s.logger.Error("Stopping DNS client", "error", err)
	}
	s.logger.Info("DNS client stopped")
}

func (s *DoHServer) requestHandler(w http.ResponseWriter, r *http.Request) {
	if ok := s.httpSemaphore.TryAcquire(1); !ok {
		s.logger.Error("semaphore limit exceeded")
		http.Error(w, "semaphore limit exceeded", http.StatusTooManyRequests)
		return
	}
	defer s.httpSemaphore.Release(1)

	reqID := dns.NewRequestID()
	logger := s.logger.With("trace-id", reqID)
	w.Header().Add("X-Trace-ID", reqID.String())

	clientIP, err := s.getClientIPAddress(r)
	if err != nil {
		logger.Error("get client ip address", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logger = logger.With("client-ip", clientIP)

	logger.Debug("serving request", "req", r)

	found := false
CONTENTTYPE_LOOP:
	for _, val := range r.Header.Values("Accept") {
		for _, contentType := range strings.Split(val, ",") {
			if strings.TrimSpace(contentType) == "application/dns-message" {
				found = true
				break CONTENTTYPE_LOOP
			}
		}
	}
	if !found {
		http.Error(w, "unknown MIME type", http.StatusBadRequest)
		return
	}

	var body []byte
	switch r.Method {
	case http.MethodGet:
		query, ok := r.URL.Query()["dns"]
		if ok && (len(query) == 1) {
			body, err = base64.RawURLEncoding.DecodeString(query[0])
		} else {
			err = fmt.Errorf("bad request")
		}
	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if (contentType != "") && (contentType != "application/dns-message") {
			err = fmt.Errorf("unknown body MIME type")
		} else {
			body, err = io.ReadAll(r.Body)
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
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	buf := s.bufPool.Get()
	defer s.bufPool.Put(buf)
	resp, err := s.dnsClient.QueryPackedMsg(r.Context(), reqID, clientIP, body, buf.([]byte))
	if err != nil {
		logger.Error("DNS query", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respHeaders := w.Header()
	respHeaders.Set("Content-Type", "application/dns-message")
	if (r.Method == http.MethodGet) && (resp.TTL != math.MaxUint32) {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", resp.TTL))
	}

	msgLen := len(resp.Msg)
	respHeaders.Set("Content-Length", strconv.Itoa(msgLen))
	n, err := w.Write(resp.Msg)
	if err != nil {
		logger.Error("could not reply", "error", err)
	} else if n != msgLen {
		logger.Error("incomplete response sent", "msg-len", msgLen, "msg-sent", n)
	}
}

func (s *DoHServer) generateSelfSignedCert(hostname, organization string, validFrom time.Time,
	validFor time.Duration,
) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature + x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	host, _, err := net.SplitHostPort(hostname)
	if (err != nil) && strings.HasSuffix(err.Error(), "missing port in address") {
		return tls.Certificate{}, fmt.Errorf("invalid hostname: %w", err)
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate certificate: %w", err)
	}

	var certBuf bytes.Buffer
	if err = pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return tls.Certificate{}, fmt.Errorf("encode certificate: %w", err)
	}

	var privBuf bytes.Buffer
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal private key: %w", err)
	}
	if err = pem.Encode(&privBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return tls.Certificate{}, fmt.Errorf("encode private key: %w", err)
	}

	return tls.X509KeyPair(certBuf.Bytes(), privBuf.Bytes())
}

func (s *DoHServer) getClientIPAddress(r *http.Request) (net.IP, error) {
	clientAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse client address: %w", err)
	}

	if _, ok := s.conf.KnownProxies[clientAddr]; !ok {
		return net.ParseIP(clientAddr), nil
	}

	switch s.conf.ProxyHeader {
	case "x-real-ip":
		if realIP := net.ParseIP(r.Header.Get(s.conf.ProxyHeader)); realIP != nil {
			return realIP, nil
		}
	case "x-forwarded-for":
		addrs := strings.Split(strings.Join(r.Header.Values(s.conf.ProxyHeader), ","), ",")
		for i := len(addrs) - 1; i >= 0; i-- {
			if addr := net.ParseIP(strings.TrimSpace(addrs[i])); addr == nil {
				return nil, fmt.Errorf("invalid proxy header value: %q", addr)
			} else {
				clientAddr = addr.String()
				if _, ok := s.conf.KnownProxies[clientAddr]; !ok {
					return addr, nil
				}
			}
		}
	case "forwarded":
		nodes := strings.Split(strings.Join(r.Header.Values(s.conf.ProxyHeader), ","), ",")
		for i := len(nodes) - 1; i >= 0; i-- {
			var proxy, client string
			for _, pair := range strings.Split(nodes[i], ";") {
				elems := strings.SplitN(strings.TrimSpace(pair), "=", 1)
				if len(elems) < 2 {
					return nil, fmt.Errorf("missing proxy header forwarded pair: %q", pair)
				}
				if len(elems[0]) < 1 {
					return nil, fmt.Errorf("empty proxy header forwarded token: %q", pair)
				}
				l := len(elems[1])
				if l < 1 {
					return nil, fmt.Errorf("empty proxy header forwarded value: %q", pair)
				}

				if (elems[1][0] == '"') || (elems[1][l-1] == '"') {
					if (elems[1][0] != elems[1][l-1]) || (l < 2) {
						return nil, fmt.Errorf("invalid proxy header forwarded value: %q", elems[1])
					}
					elems[1] = elems[1][1 : l-1]
				}

				switch elems[0] {
				case "by":
					if proxy != "" {
						return nil, fmt.Errorf("duplicate proxy header forwarded by value: %q", nodes[i])
					}
					proxy = elems[1]
				case "for":
					if client != "" {
						return nil, fmt.Errorf("duplicate proxy header forwarded for value: %q", nodes[i])
					}
					client = elems[1]
				}
			}

			if proxy == "" {
				proxy = client
			}

			proxyAddr, err := s.validateForwardedValue(proxy)
			if err != nil {
				return nil, fmt.Errorf("corrupt proxy header value %q: %w", proxy, err)
			}

			addr, err := s.validateForwardedValue(client)
			if err != nil {
				return nil, fmt.Errorf("corrupt proxy header value %q: %w", client, err)
			}

			if len(proxyAddr) == 0 {
				proxyAddr = addr
			}

			if len(proxyAddr) != 0 {
				if _, ok := s.conf.KnownProxies[proxyAddr.String()]; ok {
					if len(addr) != 0 {
						clientAddr = addr.String()
					}
				}
			}

		}
	}

	return net.ParseIP(clientAddr), nil
}

func (s *DoHServer) validateForwardedValue(value string) (net.IP, error) {
	lastPost := len(value) - 1
	pos := lastPost
	for ; pos >= 0; pos-- {
		if value[pos] == ':' {
			break
		}
	}

	var portStr string
	if pos >= 0 {
		if (pos == 0) || (pos == lastPost) {
			return nil, fmt.Errorf("empty host or port")
		}
		portStr = value[pos+1:]
		value = value[:pos]
	}

	var addr net.IP
	if strings.HasPrefix(value, "_") {
		if !s.conf.RFC7239Regexp.MatchString(value) {
			return nil, fmt.Errorf("invalid obfuscated identifier")
		}
	} else {
		addr = net.ParseIP(value)
		if addr == nil {
			return nil, fmt.Errorf("invalid IP address")
		}
		if len(portStr) > 0 {
			if port, err := strconv.Atoi(portStr); (err != nil) || (port < 0) || (port > 65535) {
				return nil, fmt.Errorf("invalid port number")
			}
		}
	}

	return addr, nil
}
