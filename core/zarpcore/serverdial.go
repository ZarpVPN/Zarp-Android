package zarpcore

// Strategy-aware dialing for the user's own server (VLESS, Trojan, Hysteria2, XHTTP).
//
// On Windows winws2 intercepts the packets of one address and port. Android has no packet interception without
// root, so the same effect is reached where the sockets are made: every connection to the server is opened by
// one of the dialers below, and only to that server.
//
//   TCP (TLS handshake)  the first write of every new connection, the TLS ClientHello, leaves as several segments
//                        (split) or with the first segment held back (disorder), cut at zapret2 markers
//   UDP (QUIC)           before the first datagram of every new flow, N fake QUIC Initials leave from the same
//                        socket, so a DPI box sees them on the same 5-tuple
//
// The sing-box protocols reach these dialers through the outbound type "zarp-dial" (a detour: the protocol
// outbound keeps its own server name, SNI, Host header and so on), Xray through its system dialer.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
)

// fakeStep is one `fake` step of a QUIC strategy: the blob is sent repeats times, optionally with a low TTL.
type fakeStep struct {
	blob    string
	repeats int
	ttl4    int // 0 keeps the socket's TTL
	ttl6    int
}

// Error classes of a failed connection to the server. They carry no addresses, names or credentials.
const (
	errClassRefused     = "refused"
	errClassTimeout     = "timeout"
	errClassUnreachable = "unreachable"
	errClassReset       = "reset"
	errClassCertificate = "certificate"
	errClassECH         = "ech"
	errClassReality     = "reality"
	errClassStatus      = "status"
	errClassTTL         = "ttl"
	errClassProtect     = "protect"
	errClassBlocked     = "blocked"
	errClassOther       = "other"
)

// classifyError maps a connection error to one of the classes above.
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return errClassRefused
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return errClassTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errClassTimeout
	}
	text := strings.ToLower(err.Error())
	words := strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_'
	})
	hasWord := func(word string) bool {
		for _, token := range words {
			if token == word {
				return true
			}
		}
		return false
	}
	switch {
	case strings.Contains(text, "zarp: ttl"):
		return errClassTTL
	case strings.Contains(text, "protect failed"):
		return errClassProtect
	case strings.Contains(text, "only dials"):
		return errClassBlocked
	case hasWord("ech") || strings.Contains(text, "encrypted client hello"):
		return errClassECH
	case hasWord("reality"):
		return errClassReality
	case hasWord("x509") || hasWord("certificate") || hasWord("pinned"):
		return errClassCertificate
	case strings.Contains(text, "connection refused") || strings.Contains(text, "actively refused"):
		return errClassRefused
	case strings.Contains(text, "i/o timeout") || strings.Contains(text, "timed out") || strings.Contains(text, "deadline exceeded") ||
		strings.Contains(text, "handshake timeout") || strings.Contains(text, "did not properly respond"):
		return errClassTimeout
	case strings.Contains(text, "no route to host") || hasWord("unreachable"):
		return errClassUnreachable
	case strings.Contains(text, "connection reset") || strings.Contains(text, "broken pipe") || hasWord("eof"):
		return errClassReset
	case strings.Contains(text, "unexpected status") || strings.Contains(text, "bad status"):
		return errClassStatus
	}
	return errClassOther
}

// serverSession holds what every dialer of one connection to the server shares.
type serverSession struct {
	host    string // the name in the link: what the protocol believes it dials
	address string // the IP address the app resolved, the one that is really dialled
	port    int
	quic    bool // the outer transport is QUIC over UDP
	tcp     *desyncSpec
	fakes   []fakeStep
	blobs   map[string][]byte
	sockets SocketFactory
	timeout time.Duration

	mu      sync.Mutex
	lastErr string
	noted   map[string]bool

	// what actually happened, for the app log and the tests
	tcpDials    atomic.Int64 // TCP connections opened to the server
	splitDials  atomic.Int64 // of them, ClientHellos that were cut up
	udpFlows    atomic.Int64 // UDP flows opened to the server
	fakeFlows   atomic.Int64 // of them, flows that got fake packets first
	fakePackets atomic.Int64 // fake packets sent
	foreign     atomic.Int64 // connections to other addresses (not covered by the strategy)
}

func (s *serverSession) dialTimeout() time.Duration {
	if s.timeout > 0 {
		return s.timeout
	}
	return 15 * time.Second
}

// fail records why a connection failed (the class only) and returns err.
func (s *serverSession) fail(err error) error {
	if class := classifyError(err); class != "" {
		s.mu.Lock()
		s.lastErr = class
		s.mu.Unlock()
	}
	return err
}

func (s *serverSession) lastClass() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// once runs f the first time key is seen.
func (s *serverSession) once(key string, f func()) {
	s.mu.Lock()
	if s.noted == nil {
		s.noted = map[string]bool{}
	}
	seen := s.noted[key]
	s.noted[key] = true
	s.mu.Unlock()
	if !seen {
		f()
	}
}

// matches reports whether host:port is the server of this session.
func (s *serverSession) matches(host string, port int) bool {
	if port != s.port {
		return false
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, s.host) {
		return true
	}
	// an IP address, in any spelling, of the link's host or of the address the app resolved
	a := net.ParseIP(host)
	if a == nil {
		return false
	}
	if b := net.ParseIP(s.host); b != nil && a.Equal(b) {
		return true
	}
	b := net.ParseIP(s.address)
	return b != nil && a.Equal(b)
}

func (s *serverSession) hostPort() string {
	return net.JoinHostPort(s.address, strconv.Itoa(s.port))
}

// control keeps the sockets of the core out of the VPN. Zarp's own app is excluded from it as well; this is the second guard.
func (s *serverSession) control(network, address string, c syscall.RawConn) error {
	if s.sockets == nil {
		return nil
	}
	var perr error
	if err := c.Control(func(fd uintptr) {
		if !s.sockets.Protect(int(fd)) {
			perr = errors.New("VpnService.protect failed")
		}
	}); err != nil {
		return err
	}
	return perr
}

func (s *serverSession) dialer() *net.Dialer {
	return &net.Dialer{Timeout: s.dialTimeout(), Control: s.control}
}

// ---------------------------------------------------------------------------------------------- TCP

// dialTCP opens a connection to the server. With a TCP strategy the TLS ClientHello that comes first on it is cut up.
func (s *serverSession) dialTCP(ctx context.Context) (net.Conn, error) {
	raw, err := s.dialer().DialContext(ctx, "tcp", s.hostPort())
	if err != nil {
		return nil, s.fail(err)
	}
	s.tcpDials.Add(1)
	tc, ok := raw.(*net.TCPConn)
	if !ok || s.tcp == nil {
		return raw, nil
	}
	return &serverTCPConn{Conn: raw, tcp: tc, spec: s.tcp, sess: s}, nil
}

// serverTCPConn cuts the first write of a connection when it is a TLS ClientHello. It embeds the net.Conn
// interface, not the *net.TCPConn, so that no file descriptor shortcut (splice, ReadFrom) can bypass Write.
type serverTCPConn struct {
	net.Conn
	tcp  *net.TCPConn
	spec *desyncSpec
	sess *serverSession
	once sync.Once
}

func (c *serverTCPConn) Write(b []byte) (int, error) {
	first := false
	c.once.Do(func() { first = true })
	if !first || !isTLSClientHello(b) {
		return c.Conn.Write(b)
	}
	// the markers follow the name that is really on the wire: with ECH that is the public name
	hostAt, host := -1, ""
	if start, _, name, ok := clientHelloSNI(b); ok {
		hostAt, host = start, name
	}
	parts := positionsAt(b, c.spec.pos, hostAt, host)
	if len(parts) == 0 {
		return c.Conn.Write(b)
	}
	c.sess.splitDials.Add(1)
	n, err := sendSegments(c.tcp, c.spec.mode, b, parts)
	if err != nil {
		return n, c.sess.fail(err)
	}
	return n, nil
}

func (c *serverTCPConn) CloseWrite() error { return c.tcp.CloseWrite() }
func (c *serverTCPConn) CloseRead() error  { return c.tcp.CloseRead() }

// ---------------------------------------------------------------------------------------------- UDP

// dialUDP opens a connected UDP socket to the server. With fakes configured, they leave before its first datagram.
func (s *serverSession) dialUDP(ctx context.Context) (net.Conn, error) {
	raw, err := s.dialer().DialContext(ctx, "udp", s.hostPort())
	if err != nil {
		return nil, s.fail(err)
	}
	s.udpFlows.Add(1)
	uc, ok := raw.(*net.UDPConn)
	if !ok || len(s.fakes) == 0 {
		return raw, nil
	}
	return &fakeUDPConn{Conn: raw, udp: uc, sess: s}, nil
}

// fakeUDPConn sends the fake packets, once, before the first datagram of the flow.
type fakeUDPConn struct {
	net.Conn
	udp  *net.UDPConn
	sess *serverSession
	once sync.Once
	err  error
}

func (c *fakeUDPConn) Write(b []byte) (int, error) {
	c.once.Do(func() {
		c.err = c.sess.sendFakes(c.udp, func(p []byte) error { _, err := c.Conn.Write(p); return err })
	})
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Write(b)
}

// listenUDP is dialUDP for callers that need an unconnected socket (Xray's QUIC transport). Whatever address
// the caller writes to, the datagrams go to the server.
func (s *serverSession) listenUDP(ctx context.Context) (net.PacketConn, *net.UDPAddr, error) {
	dest, err := net.ResolveUDPAddr("udp", s.hostPort())
	if err != nil {
		return nil, nil, s.fail(err)
	}
	network := "udp4"
	if dest.IP.To4() == nil {
		network = "udp6"
	}
	lc := net.ListenConfig{Control: s.control}
	pc, err := lc.ListenPacket(ctx, network, ":0")
	if err != nil {
		return nil, nil, s.fail(err)
	}
	s.udpFlows.Add(1)
	uc, ok := pc.(*net.UDPConn)
	if !ok || len(s.fakes) == 0 {
		return &serverPacketConn{PacketConn: pc, dest: dest}, dest, nil
	}
	return &serverPacketConn{PacketConn: pc, dest: dest, udp: uc, sess: s}, dest, nil
}

// serverPacketConn pins every datagram to the server and, when the session has fakes, sends them first.
type serverPacketConn struct {
	net.PacketConn
	dest *net.UDPAddr
	udp  *net.UDPConn
	sess *serverSession
	once sync.Once
	err  error
}

func (c *serverPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.sess != nil {
		c.once.Do(func() {
			c.err = c.sess.sendFakes(c.udp, func(p []byte) error { _, err := c.udp.WriteToUDP(p, c.dest); return err })
		})
		if c.err != nil {
			return 0, c.err
		}
	}
	return c.PacketConn.WriteTo(b, c.dest)
}

// SetReadBuffer and SetWriteBuffer let quic-go enlarge the socket buffers.
func (c *serverPacketConn) SetReadBuffer(n int) error {
	if u, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return u.SetReadBuffer(n)
	}
	return nil
}

func (c *serverPacketConn) SetWriteBuffer(n int) error {
	if u, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return u.SetWriteBuffer(n)
	}
	return nil
}

// sendFakes sends the configured fake packets through send. A step with a TTL that cannot be applied is an
// error: fakes at the normal TTL would be a different action under the same name.
func (s *serverSession) sendFakes(udp *net.UDPConn, send func([]byte) error) error {
	ip := net.ParseIP(s.address)
	v6 := ip != nil && ip.To4() == nil
	raw, err := udp.SyscallConn()
	if err != nil {
		return s.fail(err)
	}
	sent := 0
	for _, step := range s.fakes {
		payload, ok := s.blobs[step.blob]
		if !ok || len(payload) == 0 {
			return s.fail(fmt.Errorf("zarp: fake blob %q is not loaded", step.blob))
		}
		ttl := step.ttl4
		if v6 {
			ttl = step.ttl6
		}
		emit := func() error {
			for i := 0; i < step.repeats; i++ {
				if err := send(payload); err != nil {
					return err
				}
				sent++
			}
			return nil
		}
		if ttl <= 0 {
			if err := emit(); err != nil {
				return s.fail(err)
			}
			continue
		}
		if err := withTTL(raw, v6, ttl, emit); err != nil {
			return s.fail(err)
		}
	}
	s.fakeFlows.Add(1)
	s.fakePackets.Add(int64(sent))
	return nil
}

// withTTL runs fn with the socket's TTL (hop limit) set to ttl and restores the old value afterwards.
func withTTL(raw syscall.RawConn, v6 bool, ttl int, fn func() error) error {
	var old int
	var serr error
	if err := raw.Control(func(fd uintptr) { old, serr = getTTL(fd, v6) }); err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("zarp: ttl is not readable: %w", serr)
	}
	if err := raw.Control(func(fd uintptr) { serr = setTTL(fd, v6, ttl) }); err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("zarp: ttl cannot be set: %w", serr)
	}
	ferr := fn()
	if err := raw.Control(func(fd uintptr) { serr = setTTL(fd, v6, old) }); err != nil {
		return err
	}
	if ferr != nil {
		return ferr
	}
	if serr != nil {
		return fmt.Errorf("zarp: ttl cannot be restored: %w", serr)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------- other addresses

// dialForeign connects to an address that is not the server (for example the download address of an XHTTP
// downloadSettings). The strategy is paired with one server and is not applied to anything else; this is
// counted and noted once so that the app can say so.
func (s *serverSession) dialForeign(ctx context.Context, network, address string) (net.Conn, error) {
	s.foreign.Add(1)
	return s.dialer().DialContext(ctx, network, address)
}
