package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	_ "unsafe"

	"doh/config"

	"github.com/miekg/dns"
)

type RequestID [4]uint16

func (r RequestID) String() string {
	return fmt.Sprintf("%04x-%04x-%04x-%04x", r[0], r[1], r[2], r[3])
}

func NewRequestID() RequestID {
	return RequestID{
		uint16(fastRandN(1 << 16)), uint16(fastRandN(1 << 16)), uint16(fastRandN(1 << 16)),
		uint16(fastRandN(1 << 16)),
	}
}

type Client struct {
	ctx           context.Context
	conf          *config.DoHServer
	msgPool       sync.Pool
	clientPool    sync.Pool
	connPool      *ConnPool
	resolvers     []config.DNSResolver
	resolverCount uint32
}

type Response struct {
	Msg []byte
	TTL uint32
}

//go:noescape
//go:linkname fastRandN runtime.fastrandn
func fastRandN(n uint32) uint32

func NewClient(ctx context.Context, conf *config.DoHServer) (*Client, error) {
	connPool, err := NewConnPool(conf.ConnPool.MaxOpen, conf.ConnPool.MaxIdle, conf.ConnPool.MaxHostOpen,
		conf.ConnPool.MaxHostIdle, conf.ConnPool.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("connection pool: %w", err)
	}
	dnsClient := &Client{
		ctx:  ctx,
		conf: conf,
		msgPool: sync.Pool{
			New: func() any {
				return &dns.Msg{}
			},
		},
		clientPool: sync.Pool{
			New: func() any {
				return &dns.Client{
					UDPSize: uint16(conf.UDPSize),
				}
			},
		},
		connPool: connPool,
	}

	dnsClient.resolvers = conf.DNSResolvers[:]
	dnsClient.resolverCount = uint32(len(dnsClient.resolvers))

	return dnsClient, nil
}

func (c *Client) Start() {
}

func (c *Client) Stop() {
}

func (c *Client) Query(ctx context.Context, reqID RequestID, clientIP net.IP, msg *dns.Msg) (*dns.Msg, error) {
	msgID := msg.Id
	msg.Id = reqID[0]
	if c.conf.Debug {
		log.Printf("[%v] orig %x: %#v", reqID, msgID, msg)
	}

	optRR := msg.IsEdns0()
	if (optRR == nil) && c.conf.ForceEDNS {
		optRR = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
				Class:  uint16(c.conf.UDPSize),
			},
		}
		msg.Extra = append(msg.Extra, optRR)
	}

	if optRR != nil {
		var ecsOpt *dns.EDNS0_SUBNET
		for _, option := range optRR.Option {
			if option.Option() == dns.EDNS0SUBNET {
				ecsOpt = option.(*dns.EDNS0_SUBNET)
				break
			}
		}

		isIPv6 := clientIP.To4() == nil
		var family uint16
		var netmask uint8
		if isIPv6 {
			family = 2
			netmask = uint8(c.conf.ECS6PrefixLen)
		} else {
			family = 1
			netmask = uint8(c.conf.ECS4PrefixLen)
		}

		if ecsOpt != nil {
			if ecsOpt.SourceNetmask > netmask {
				ecsOpt.SourceNetmask = netmask
				ecsOpt.Address.Mask(net.CIDRMask(int(netmask), len(ecsOpt.Address)))
			}
		} else {
			if c.conf.ForceECS {
				addr := clientIP[:]
				if isIPv6 {
					addr.Mask(net.CIDRMask(c.conf.ECS6PrefixLen, net.IPv6len*8))
				} else {
					addr.Mask(net.CIDRMask(c.conf.ECS4PrefixLen, net.IPv4len*8))
				}

				ecsOpt = &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        family,
					SourceNetmask: netmask,
					Address:       clientIP,
				}

				optRR.Option = append(optRR.Option, ecsOpt)
			}
		}
	}

	client := c.clientPool.Get().(*dns.Client)
	defer c.clientPool.Put(client)

	resolver := c.resolvers[fastRandN(c.resolverCount)]
	client.Net = resolver.Net
	if c.conf.Debug {
		log.Printf("[%v] req %x to %v: %#v", reqID, msgID, resolver, msg)
	}

	conn, err := c.connPool.Get(resolver.Net, resolver.Addr)
	if err != nil {
		return nil, fmt.Errorf("could not dial connection for %v: %w", resolver, err)
	}
	defer func() {
		if err = c.connPool.Put(conn); err != nil {
			log.Printf("error putting connection %v back into cache: %v", resolver, err)
		}
	}()

	rrMsg, _, err := client.ExchangeWithConn(msg, conn)
	if err != nil {
		return nil, fmt.Errorf("could not query %s: %w", resolver.Addr, err)
	}
	if c.conf.Debug {
		log.Printf("[%v] resp %x: %#v", reqID, msgID, rrMsg)
	}

	rrMsg.Id = msgID

	return rrMsg, nil
}

func (c *Client) QueryPackedMsg(ctx context.Context, reqID RequestID, clientIP net.IP, msg []byte) (*Response, error) {
	queryMsg := c.msgPool.Get().(*dns.Msg)
	defer c.msgPool.Put(queryMsg)

	err := queryMsg.Unpack(msg)
	if err != nil {
		return nil, fmt.Errorf("could not unpack query: %w", err)
	}

	rrMsg, err := c.Query(ctx, reqID, clientIP, queryMsg)
	if err != nil {
		return nil, err
	}

	resp, err := rrMsg.Pack()
	if err != nil {
		return nil, fmt.Errorf("could not pack response: %w", err)
	}

	return &Response{
		Msg: resp,
		TTL: c.GetTTL(rrMsg),
	}, nil
}

func (c *Client) GetTTL(msg *dns.Msg) uint32 {
	minTTL := uint32(1<<32 - 1)

	for _, dnsRR := range msg.Ns {
		ttl := dnsRR.Header().Ttl
		if ttl < minTTL {
			minTTL = ttl
		}
	}

	for _, dnsRR := range msg.Answer {
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
