# DNS over HTTPS forwarder
This is a bare bones DNS over HTTPS proxy that listens for requests over DoH and forwards them to given DNS servers.

## Usage
```
Usage of doh:
  -debug
    	Show debug info
  -httpWorkers int
    	Number of workers to handle incoming requests (default 1000)
  -knownProxies string
    	Semicolon separated list of upstream proxies trusted to send valid client IP address
  -listen string
    	Semicolon separated list of addresses to listen on for incoming connections; to enable TLS use <addr:port>,<cert>,<key>[,clientCAs] instead (default "127.0.0.1:8053")
  -resolvers string
    	Semicolon separated list of DNS resolvers to forward requests to, specified as <network>,<addr:port>; append '-tls' to the TCP network for DNS over TLS (e.g. 'tcp4-tls') (default "udp,127.0.0.1:53")
```

## TODO
* EDNS client subnet
* DoH client
* TCP connection pooling
* better (env/file?) config
* rate limiting

## License
This project is licensed under the 2-Clause BSD License - see the [LICENSE.md](LICENSE.md) file for details
