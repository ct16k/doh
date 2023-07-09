package dns

import (
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type connKey [2]string

type dnsConn struct {
	idle chan *dns.Conn
	open atomic.Int32
}

type ConnPool struct {
	idleConn     map[connKey]*dnsConn
	reqChan      chan *dnsConn
	connLock     sync.Mutex
	open         atomic.Int32
	idle         atomic.Int32
	maxOpen      int32
	maxIdle      int32
	maxHostOpen  int32
	maxHostIdle  int32
	pollInterval time.Duration
}

func NewConnPool(maxOpen, maxIdle, maxHostOpen, maxHostIdle int32, pollInterval time.Duration) (*ConnPool, error) {
	if maxOpen < 1 {
		return nil, fmt.Errorf("invalid number of total open connections: %d", maxOpen)
	}
	if maxIdle < 1 {
		return nil, fmt.Errorf("invalid number of total idle connections: %d", maxIdle)
	}
	if maxIdle > maxOpen {
		return nil, fmt.Errorf("number of idle connections (%d) higher than limit (%d)", maxIdle, maxOpen)
	}

	if maxHostOpen < 1 {
		return nil, fmt.Errorf("invalid number of per host open connections: %d", maxHostOpen)
	}
	if maxHostOpen > maxOpen {
		return nil, fmt.Errorf("number of per host open connections (%d) higher than limit (%d)", maxHostOpen, maxOpen)
	}
	if maxHostIdle < 1 {
		return nil, fmt.Errorf("invalid number of per host idle connections: %d", maxHostIdle)
	}
	if maxHostIdle > maxIdle {
		return nil, fmt.Errorf("number of per host idle connections (%d) higher than limit (%d)", maxHostIdle, maxIdle)
	}
	if maxHostIdle > maxHostOpen {
		return nil, fmt.Errorf("number of per host idle connections (%d) higher than limit (%d)", maxHostIdle,
			maxHostOpen)
	}

	connPool := &ConnPool{
		idleConn:     make(map[connKey]*dnsConn),
		reqChan:      make(chan *dnsConn, maxOpen),
		maxOpen:      maxOpen,
		maxIdle:      maxIdle,
		maxHostOpen:  maxHostOpen,
		maxHostIdle:  maxHostIdle,
		pollInterval: pollInterval,
	}

	go func() {
		for dest := range connPool.reqChan {
			connPool.newConnectionHandler(dest)
		}
	}()

	return connPool, nil
}

func (p *ConnPool) Stop() error {
	p.connLock.Lock()
	defer p.connLock.Unlock()

	close(p.reqChan)

	var errs []error
	for k, l := range p.idleConn {
	DRAINLOOP:
		for {
			select {
			case c := <-l.idle:
				if c != nil {
					if err := c.Close(); err != nil {
						errs = append(errs, err)
					}
				}
			default:
				close(l.idle)
				break DRAINLOOP
			}
		}
		delete(p.idleConn, k)
	}

	return errors.Join(errs...)
}

func (p *ConnPool) Get(network, addr string) (*dns.Conn, error) {
	l := p.getConnList(connKey{network, addr})

	for {
		select {
		case c, more := <-l.idle: // retrieve an idle connection
			if !more {
				return nil, fmt.Errorf("channel closed")
			}
			p.idle.Add(-1)
			if c == nil {
				return dns.Dial(network, addr)
			}

			if err := p.connCheck(c); err != nil {
				log.Printf("closing bad idle connection %s://%s: %v", network, addr, err)
				l.open.Add(-1)
				p.open.Add(-1)
				if err = c.Close(); err != nil {
					log.Printf("error closing connection %s://%s: %v", network, addr, err)
				}

				continue
			}
			return c, nil
		default:
			p.reqChan <- l      // request a new connection
			c, more := <-l.idle // wait for a connection to become available
			if !more {
				return nil, fmt.Errorf("channel closed")
			}
			p.idle.Add(-1)
			if c == nil {
				return dns.Dial(network, addr)
			}

			if err := p.connCheck(c); err != nil {
				log.Printf("closing bad idle connection %s://%s: %v", network, addr, err)
				l.open.Add(-1)
				p.open.Add(-1)
				if err = c.Close(); err != nil {
					log.Printf("error closing connection %s://%s: %v", network, addr, err)
				}

				continue
			}
			return c, nil
		}
	}
}

func (p *ConnPool) Put(c *dns.Conn) error {
	network := c.RemoteAddr().Network()
	addr := c.RemoteAddr().String()
	l := p.getConnList(connKey{network, addr})

	if network == "udp" {
		l.open.Add(-1)
		p.open.Add(-1)
		return c.Close()
	}

	if err := p.connCheck(c); err != nil {
		l.open.Add(-1)
		p.open.Add(-1)
		if closeErr := c.Close(); closeErr != nil {
			log.Printf("error closing bad idle connection %s://%s: %v", network, addr, closeErr)
		}
		return err
	}

	if p.idle.Load() >= p.maxIdle {
		l.open.Add(-1)
		p.open.Add(-1)
		return c.Close()
	}

	if int32(len(l.idle)) >= p.maxHostIdle {
		l.open.Add(-1)
		p.open.Add(-1)
		return c.Close()
	}

	select {
	case l.idle <- c:
		p.idle.Add(1)
	default:
		l.open.Add(-1)
		p.open.Add(-1)
		return c.Close()
	}

	return nil
}

func (p *ConnPool) Close(c *dns.Conn) error {
	l := p.getConnList(connKey{c.RemoteAddr().Network(), c.RemoteAddr().String()})

	l.open.Add(-1)
	p.open.Add(-1)
	return c.Close()
}

func (p *ConnPool) getConnList(addr connKey) *dnsConn {
	p.connLock.Lock()
	defer p.connLock.Unlock()

	addr[0] = strings.TrimSuffix(addr[0], "-tls")
	l := p.idleConn[addr]
	if l == nil {
		l = &dnsConn{
			idle: make(chan *dns.Conn, p.maxHostOpen),
		}
		p.idleConn[addr] = l
	}

	return l
}

func (p *ConnPool) newConnectionHandler(l *dnsConn) {
	for {
		if (p.open.Load() < p.maxOpen) && (l.open.Load() < p.maxHostOpen) {
			select {
			case l.idle <- nil:
				l.open.Add(1)
				p.open.Add(1)
				p.idle.Add(1)
				return
			default:
				break
			}
		}
		time.Sleep(p.pollInterval)
	}
}

func (p *ConnPool) connCheck(conn *dns.Conn) error {
	rc, err := conn.Conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}

	var sysErr error = nil
	err = rc.Read(func(fd uintptr) bool {
		buf := []byte{0}
		var n int

		n, err = syscall.Read(syscall.Handle(fd), buf)
		switch {
		case n == 0 && err == nil:
			sysErr = io.EOF
		case n > 0:
			sysErr = syscall.ERANGE
		case err == syscall.EAGAIN || err == syscall.EWOULDBLOCK:
			sysErr = nil
		default:
			sysErr = err
		}

		return true
	})

	if err != nil {
		return err
	}

	return sysErr
}
