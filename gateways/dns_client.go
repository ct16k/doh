package gateways

import (
	"context"
	"fmt"
	"log"
	"math"
	"math/rand"

	"doh/domain"

	"github.com/miekg/dns"
)

type DNSClient struct {
	ctx           context.Context
	config        *domain.DoHConfig
	resolvers     []domain.DNSResolver
	resolverCount int
}

type DNSResponse struct {
	Msg []byte
	TTL uint32
}

func NewDNSClient(ctx context.Context) *DNSClient {
	config := ctx.Value("config").(*domain.DoHConfig)
	dnsClient := &DNSClient{
		ctx:    ctx,
		config: config,
	}

	dnsClient.resolvers = append(dnsClient.resolvers, config.DNSResolvers...)
	dnsClient.resolverCount = len(dnsClient.resolvers)

	return dnsClient
}

func (c *DNSClient) Start() {
}

func (c *DNSClient) Stop() {
}

func (c *DNSClient) QueryDNS(msg []byte) (*DNSResponse, error) {
	var queryMsg dns.Msg
	err := queryMsg.Unpack(msg)
	if err != nil {
		return nil, fmt.Errorf("could not unpack query: %v", err)
	}
	if c.config.Debug {
		log.Printf("%#v", queryMsg)
	}

	resolver := c.resolvers[rand.Intn(c.resolverCount)]
	client := &dns.Client{
		Net: resolver.Net,
	}
	rrMsg, _, err := client.Exchange(&queryMsg, resolver.Addr)
	if err != nil {
		return nil, fmt.Errorf("could not query %s: %v", resolver.Addr, err)
	}
	if c.config.Debug {
		log.Printf("%#v", rrMsg)
	}

	resp, err := rrMsg.Pack()
	if err != nil {
		return nil, fmt.Errorf("could not pack response: %v", err)
	}

	return &DNSResponse{
		Msg: resp,
		TTL: c.GetTTL(rrMsg),
	}, nil
}

func (c *DNSClient) GetTTL(msg *dns.Msg) uint32 {
	minTTL := uint32(math.MaxUint32)

	for _, dnsRR := range msg.Answer {
		ttl := dnsRR.Header().Ttl
		if ttl < minTTL {
			minTTL = ttl
		}
	}

	for _, dnsRR := range msg.Ns {
		ttl := dnsRR.Header().Ttl
		if ttl < minTTL {
			minTTL = ttl
		}
	}

	for _, dnsRR := range msg.Extra {
		ttl := dnsRR.Header().Ttl
		if ttl < minTTL {
			minTTL = ttl
		}
	}

	return minTTL
}
