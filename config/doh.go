package config

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type DoHServer struct {
	KnownProxies  map[string]struct{}
	RFC7239Regexp *regexp.Regexp
	ProxyHeader   string
	ListenAddrs   []ListenAddr
	DNSResolvers  []DNSResolver
	HTTPWorkers   int64
	ConnPool      ConnPool
	UDPSize       int
	ECS4PrefixLen int
	ECS6PrefixLen int
	ForceEDNS     bool
	ForceECS      bool
	LogLevel      int
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

type ConnPool struct {
	MaxOpen      int32
	MaxIdle      int32
	MaxHostOpen  int32
	MaxHostIdle  int32
	PollInterval time.Duration
}

func (r DNSResolver) String() string {
	return fmt.Sprintf("%s://%s", r.Net, r.Addr)
}

type ContextKey string

const (
	ListDelimiter  = ";"
	FieldDelimiter = ","
)

func Get() (*DoHServer, error) {
	var listenAddr, knownProxies, dnsResolvers, connPool string
	conf := &DoHServer{
		KnownProxies:  make(map[string]struct{}),
		RFC7239Regexp: regexp.MustCompile("^_[A-Za-z0-9._-]+$"),
	}

	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8053",
		"Semicolon separated list of addresses to listen on for incoming connections; to enable TLS use <addr:port>,<cert>,<key>[,clientCAs] instead")
	flag.StringVar(&conf.ProxyHeader, "proxyHeader", "Forwarded",
		"Request header whose value will be checked for the client address")
	flag.StringVar(&knownProxies, "knownProxies", "",
		"Semicolon separated list of upstream proxies trusted to send valid client IP address")
	flag.Int64Var(&conf.HTTPWorkers, "httpWorkers", 1000,
		"Number of workers to handle incoming requests")
	flag.StringVar(&dnsResolvers, "resolvers", "",
		"Semicolon separated list of DNS resolvers to forward requests to, specified as <network>,<addr:port>; append '-tls' to the TCP network for DNS over TLS (e.g. 'tcp4-tls')")
	flag.BoolVar(&conf.ForceEDNS, "forceEDNS", true, "Force EDNS queries")
	flag.IntVar(&conf.UDPSize, "udpSize", 4096, "UDP buffer size for forced EDNS")
	flag.BoolVar(&conf.ForceECS, "forceECS", false, "Force EDNS CLient Subnet; implies forced EDNS")
	flag.IntVar(&conf.ECS4PrefixLen, "ecs4Prefix", 24, "ECS IPv4 source prefix length")
	flag.IntVar(&conf.ECS6PrefixLen, "ecs6Prefix", 56, "ECS IPv6 source prefix length")
	flag.StringVar(&connPool, "connPool", "10000,1000,1000,100,100ms",
		"Connection pool configuration, specified as <maxOpen>,<maxIdle>,<maxHostOpen>,<maxHostIdle>,<pollInterval>")
	flag.IntVar(&conf.LogLevel, "logLevel", int(slog.LevelInfo), "Set log level")

	flag.Parse()

	if conf.HTTPWorkers < 1 {
		flag.Usage()
		return nil, fmt.Errorf("invalid number of workers")
	}

	if (conf.UDPSize < 1) && (conf.UDPSize >= 1<<16) {
		flag.Usage()
		return nil, fmt.Errorf("invalid UDP buffer size")
	}

	if conf.ForceECS {
		conf.ForceEDNS = true
	}

	if (conf.ECS4PrefixLen < 0) && (conf.ECS4PrefixLen > 32) {
		flag.Usage()
		return nil, fmt.Errorf("invalid ECS IPv4 source prefix length")
	}

	if (conf.ECS6PrefixLen < 0) && (conf.ECS6PrefixLen > 128) {
		flag.Usage()
		return nil, fmt.Errorf("invalid ECS IPv6 source prefix length")
	}

	connPoolCfg := strings.Split(connPool, FieldDelimiter)
	if len(connPoolCfg) != 5 {
		flag.Usage()
		return nil, fmt.Errorf("invalid connection pool configuration: %s", connPool)
	}
	if i, err := strconv.Atoi(connPoolCfg[0]); err != nil {
		flag.Usage()
		return nil, fmt.Errorf("invalid max open connections: %s", err)
	} else {
		conf.ConnPool.MaxOpen = int32(i)
	}
	if i, err := strconv.Atoi(connPoolCfg[1]); err != nil {
		flag.Usage()
		return nil, fmt.Errorf("invalid max idle connections: %s", err)
	} else {
		conf.ConnPool.MaxIdle = int32(i)
	}
	if i, err := strconv.Atoi(connPoolCfg[2]); err != nil {
		flag.Usage()
		return nil, fmt.Errorf("invalid max per host open connections: %s", err)
	} else {
		conf.ConnPool.MaxHostOpen = int32(i)
	}
	if i, err := strconv.Atoi(connPoolCfg[3]); err != nil {
		flag.Usage()
		return nil, fmt.Errorf("invalid max per host idle connections: %s", err)
	} else {
		conf.ConnPool.MaxHostIdle = int32(i)
	}
	if d, err := time.ParseDuration(connPoolCfg[4]); err != nil {
		flag.Usage()
		return nil, fmt.Errorf("invalid poll interval duration: %s", err)
	} else {
		conf.ConnPool.PollInterval = d
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

		conf.ListenAddrs = append(conf.ListenAddrs, ListenAddr{
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

	conf.ProxyHeader = strings.ToLower(conf.ProxyHeader)
	switch conf.ProxyHeader {
	case "x-real-ip":
	case "x-forwarded-for":
	case "forwarded":
	default:
		flag.Usage()
		return nil, fmt.Errorf("unsupported proxy header: %s", conf.ProxyHeader)
	}

	addrs = make(map[string]struct{})
	for _, addr := range strings.Split(knownProxies, ListDelimiter) {
		if addr == "" {
			continue
		}

		if strings.HasPrefix(addr, "_") {
			if !conf.RFC7239Regexp.MatchString(addr) {
				return nil, fmt.Errorf("invalid proxy: %s", addr)
			}
		} else {
			ip := net.ParseIP(addr)
			if ip == nil {
				return nil, fmt.Errorf("invalid proxy: %s", addr)
			}
			addr = ip.String()
		}

		if _, ok := addrs[addr]; ok {
			return nil, fmt.Errorf("duplicate proxy: %s", addr)
		}

		conf.KnownProxies[addr] = struct{}{}
		addrs[addr] = struct{}{}
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

		network = strings.ToLower(fields[0])
		addr = fields[1]

		if host, port, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("invalid resolver: %w", err)
		} else {
			addr = fmt.Sprintf("%s:%s", net.ParseIP(host).String(), port)
		}

		if _, ok := addrs[strs]; ok {
			return nil, fmt.Errorf("duplicate resolver: %s", strs)
		}
		addrs[strs] = struct{}{}

		conf.DNSResolvers = append(conf.DNSResolvers, DNSResolver{
			Net:  network,
			Addr: addr,
		})
	}
	if len(addrs) == 0 {
		systemConfig := getSystemConfig()
		if systemConfig.err != nil {
			return nil, fmt.Errorf("could not read system resolvers: %w", systemConfig.err)
		}

		for _, addr := range systemConfig.servers {
			if _, ok := addrs[addr]; ok {
				slog.Error("duplicate resolver", "addr", addr)
				continue
			}
			addrs[addr] = struct{}{}

			conf.DNSResolvers = append(conf.DNSResolvers, DNSResolver{
				Net:  "udp",
				Addr: addr,
			})
		}
	}
	if len(addrs) == 0 {
		flag.Usage()
		return nil, fmt.Errorf("no resolvers to forward to")
	}

	return conf, nil
}
