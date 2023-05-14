# DNS over HTTPS forwarder
This is a bare bones DNS over HTTPS proxy that listens for requests over DoH and forwards them to given DNS servers.

## Usage
```
Usage of doh:
Usage of D:\Projects\doh\doh.exe:
  -connPool string
        Connection pool configuration, specified as <maxOpen>,<maxIdle>,<maxHostOpen>,<maxHostIdle>,<pollInterval> (default "10000,1000,1000,100,100ms")
  -debug
        Show debug info
  -ecs4Prefix int
        ECS IPv4 source prefix length (default 24)
  -ecs6Prefix int
        ECS IPv6 source prefix length (default 56)
  -forceECS
        Force EDNS CLient Subnet; implies forced EDNS
  -forceEDNS
        Force EDNS queries (default true)
  -httpWorkers int
        Number of workers to handle incoming requests (default 1000)
  -knownProxies string
        Semicolon separated list of upstream proxies trusted to send valid client IP address
  -listen string
        Semicolon separated list of addresses to listen on for incoming connections; to enable TLS use <addr:port>,<cert>,<key>[,clientCAs] instead (default "127.0.0.1:8053")
  -proxyHeader string
        Request header whose value will be checked for the client address (default "Forwarded")
  -resolvers string
        Semicolon separated list of DNS resolvers to forward requests to, specified as <network>,<addr:port>; append '-tls' to the TCP network for DNS over TLS (e.g. 'tcp4-tls')
  -udpSize int
        UDP buffer size for forced EDNS (default 4096)
```

## TODO
* DNSSEC validation
* DoH client
* proxy protocol support
* better (env/file?) config
* rate limiting
* tests!

## License
This project is licensed under the 2-Clause BSD License - see the [LICENSE.md](LICENSE.md) file for details
