package domain

import (
	"flag"
	"fmt"
	"net"
	"strings"
)

type DoHConfig struct {
	KnownProxies map[string]struct{}
	ListenAddrs  []ListenAddr
	DNSResolvers []DNSResolver
	HTTPWorkers  int64
	Debug        bool
}

type ListenAddr struct {
	Addr      string
	CertFile  string
	KeyFile   string
	ClientCAs string
}

type DNSResolver struct {
	Net  string
	Addr string
}

type ContextKey string

const (
	ListDelimiter  = ";"
	FieldDelimiter = ","
)

func GetConfig() (*DoHConfig, error) {
	var listenAddr, knownProxies, dnsResolvers string
	config := &DoHConfig{
		KnownProxies: make(map[string]struct{}),
	}

	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8053",
		"Semicolon separated list of addresses to listen on for incoming connections; to enable TLS use <addr:port>,<cert>,<key>[,clientCAs] instead")
	flag.StringVar(&knownProxies, "knownProxies", "",
		"Semicolon separated list of upstream proxies trusted to send valid client IP address")
	flag.Int64Var(&config.HTTPWorkers, "httpWorkers", 1000,
		"Number of workers to handle incoming requests")
	flag.StringVar(&dnsResolvers, "resolvers", "udp,127.0.0.1:53",
		"Semicolon separated list of DNS resolvers to forward requests to, specified as <network>,<addr:port>; append '-tls' to the TCP network for DNS over TLS (e.g. 'tcp4-tls')")
	flag.BoolVar(&config.Debug, "debug", false, "Show debug info")

	flag.Parse()

	if config.HTTPWorkers < 1 {
		flag.Usage()
		return nil, fmt.Errorf("invalid number of workers")
	}

	addrs := make(map[string]struct{})
	for _, strs := range strings.Split(listenAddr, ListDelimiter) {
		if strs == "" {
			continue
		}

		var addr, cert, key, clientCAs string
		fields := strings.Split(strs, FieldDelimiter)
		fieldCount := len(fields)

		addr = fields[0]
		if fieldCount == 4 {
			cert = fields[1]
			key = fields[2]
			clientCAs = fields[3]
		} else if fieldCount == 3 {
			cert = fields[1]
			key = fields[2]
		} else if (fieldCount != 1) || (addr == "") {
			flag.Usage()
			return nil, fmt.Errorf("invalid listen addr: %s", strs)
		}

		if _, ok := addrs[strs]; ok {
			return nil, fmt.Errorf("duplicate listen address: %s", strs)
		}
		addrs[strs] = struct{}{}

		config.ListenAddrs = append(config.ListenAddrs, ListenAddr{
			Addr:      addr,
			CertFile:  cert,
			KeyFile:   key,
			ClientCAs: clientCAs,
		})
	}
	if len(addrs) == 0 {
		flag.Usage()
		return nil, fmt.Errorf("no address to listen on")
	}

	addrs = make(map[string]struct{})
	for _, addr := range strings.Split(knownProxies, ListDelimiter) {
		if addr == "" {
			continue
		}

		if _, ok := addrs[addr]; ok {
			return nil, fmt.Errorf("duplicate proxy address: %s", addr)
		}
		addrs[addr] = struct{}{}

		if strings.HasPrefix(addr, "_") {
			config.KnownProxies[addr] = struct{}{}
		} else {
			ip := net.ParseIP(addr)
			if ip != nil {
				config.KnownProxies[string(ip)] = struct{}{}
			}
		}
	}

	addrs = make(map[string]struct{})
	for _, strs := range strings.Split(dnsResolvers, ListDelimiter) {
		if strs == "" {
			continue
		}

		var network, addr string
		fields := strings.Split(strs, FieldDelimiter)
		if len(fields) != 2 {
			flag.Usage()
			return nil, fmt.Errorf("invalid resolver: %s", strs)
		}

		network = fields[0]
		addr = fields[1]

		if _, ok := addrs[strs]; ok {
			return nil, fmt.Errorf("duplicate resolver: %s", strs)
		}
		addrs[strs] = struct{}{}

		config.DNSResolvers = append(config.DNSResolvers, DNSResolver{
			Net:  network,
			Addr: addr,
		})
	}
	if len(addrs) == 0 {
		flag.Usage()
		return nil, fmt.Errorf("no resolvers to forward to")
	}

	return config, nil
}
