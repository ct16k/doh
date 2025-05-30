package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	_ "unsafe"

	"doh/config"

	"github.com/coocood/freecache"
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
	logger        *slog.Logger
	msgPool       sync.Pool
	clientPool    sync.Pool
	connPool      *ConnPool
	cache         *freecache.Cache
	cacheTimer    freecache.StoppableTimer
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

func NewClient(ctx context.Context, conf *config.DoHServer, logger *slog.Logger) (*Client, error) {
	connPool, err := NewConnPool(logger, conf.ConnPool.MaxOpen, conf.ConnPool.MaxIdle, conf.ConnPool.MaxHostOpen,
		conf.ConnPool.MaxHostIdle, conf.ConnPool.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("connection pool: %w", err)
	}
	dnsClient := &Client{
		ctx:    ctx,
		conf:   conf,
		logger: logger,
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

	if conf.CacheSize > 0 {
		dnsClient.cacheTimer = freecache.NewCachedTimer()
		dnsClient.cache = freecache.NewCacheCustomTimer(conf.CacheSize, dnsClient.cacheTimer)
	}

	dnsClient.resolvers = conf.DNSResolvers[:]
	dnsClient.resolverCount = uint32(len(dnsClient.resolvers))

	return dnsClient, nil
}

func (c *Client) Start() {
}

func (c *Client) Stop() error {
	if err := c.connPool.Stop(); err != nil {
		return fmt.Errorf("connection pool: %w", err)
	}

	if c.cacheTimer != nil {
		c.cacheTimer.Stop()
	}

	return nil
}

func (c *Client) Query(ctx context.Context, logger *slog.Logger, reqID RequestID, clientIP net.IP, msg *dns.Msg) (*dns.Msg, error) {
	logger.Debug("query", "msg", msg)

	client := c.clientPool.Get().(*dns.Client)
	defer c.clientPool.Put(client)

	resolver := c.resolvers[fastRandN(c.resolverCount)]
	client.Net = resolver.Net
	logger.Debug("request", "resolver", resolver, "msg", msg)

	conn, err := c.connPool.Get(resolver.Net, resolver.Addr)
	if err != nil {
		return nil, fmt.Errorf("could not dial connection for %v: %w", resolver, err)
	}

	rrMsg, _, err := client.ExchangeWithConnContext(ctx, msg, conn)
	if err != nil {
		return nil, fmt.Errorf("could not query %s: %w", resolver.Addr, err)
	}
	logger.Debug("response", "rrMsg", rrMsg)

	defer func() {
		if err = c.connPool.Put(conn); err != nil {
			logger.Error("putting connection back into cache", "resolver", resolver, "error", err)
		}
	}()

	if rrMsg.Id != msg.Id {
		return nil, fmt.Errorf("message ID mismatch: got %04x, expected %04x", rrMsg.Id, msg.Id)
	}

	return rrMsg, nil
}

func (c *Client) QueryPackedMsg(ctx context.Context, reqID RequestID, clientIP net.IP, msg []byte,
	buf []byte,
) (*Response, error) {
	queryMsg := c.msgPool.Get().(*dns.Msg)
	defer c.msgPool.Put(queryMsg)

	err := queryMsg.Unpack(msg)
	if err != nil {
		return nil, fmt.Errorf("could not unpack query: %w", err)
	}

	msgID := queryMsg.Id
	queryMsg.Id = reqID[0]
	logger := c.logger.With("trace-id", reqID, "msg-id", msgID)

	var cacheKeyBuilder strings.Builder
	var cacheKey []byte
	var resp []byte
	var ttl uint32

	if c.cache != nil {
		if ecs := c.checkEDNS0(clientIP, queryMsg); ecs != nil {
			cacheKeyBuilder.WriteString(ecs.String())
		}

		for _, q := range queryMsg.Question {
			cacheKeyBuilder.WriteString(q.String())
		}
		cacheKey = []byte(cacheKeyBuilder.String())

		resp, err = c.cache.Peek(cacheKey)
		if err == nil {
			ttl, err = c.cache.TTL(cacheKey)
			binary.BigEndian.PutUint16(resp, msgID)
			logger.Debug("cached response", "msg", resp)
		}
	}

	if (c.cache == nil) || (err != nil) {
		var rrMsg *dns.Msg
		rrMsg, err = c.Query(ctx, logger, reqID, clientIP, queryMsg)
		if err != nil {
			return nil, err
		}
		rrMsg.Id = msgID

		resp, err = rrMsg.PackBuffer(buf)
		if err != nil {
			return nil, fmt.Errorf("could not pack response: %w", err)
		}

		ttl = c.GetTTL(rrMsg)
	}

	if c.cache != nil {
		if err = c.cache.Set(cacheKey, resp, int(ttl)); err != nil {
			logger.Error("could not cache record", "key", string(cacheKey), "error", err)
		}
	}

	return &Response{
		Msg: resp,
		TTL: ttl,
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

func (c *Client) checkEDNS0(clientIP net.IP, msg *dns.Msg) *dns.EDNS0_SUBNET {
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

	var ecsOpt *dns.EDNS0_SUBNET
	if optRR != nil {
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

	return ecsOpt
}
