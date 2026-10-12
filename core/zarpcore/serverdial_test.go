package zarpcore

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// realClientHello is the first record of an actual crypto/tls handshake for name.
func realClientHello(t *testing.T, name string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	}()
	buf := make([]byte, 1<<15)
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestClientHelloSNI(t *testing.T) {
	hello := realClientHello(t, "front.example.com")
	if !isTLSClientHello(hello) {
		t.Fatal("not recognised as a ClientHello")
	}
	start, end, host, ok := clientHelloSNI(hello)
	if !ok || host != "front.example.com" || string(hello[start:end]) != host {
		t.Fatalf("clientHelloSNI = %d %d %q %v", start, end, host, ok)
	}
	// without a server name there is nothing to find
	if _, _, _, ok := clientHelloSNI(realClientHello(t, "")); ok {
		t.Fatal("a ClientHello without SNI reported one")
	}
	// truncated and wrong records never panic
	for i := 0; i < len(hello); i += 7 {
		clientHelloSNI(hello[:i])
	}
	for _, bad := range [][]byte{nil, {0x16}, {0x17, 3, 3, 0, 0, 0}, bytes.Repeat([]byte{0xff}, 64)} {
		if _, _, _, ok := clientHelloSNI(bad); ok {
			t.Fatalf("%x accepted", bad)
		}
		if isTLSClientHello(bad) && bad[0] != 0x16 {
			t.Fatalf("%x taken for a ClientHello", bad)
		}
	}
}

func TestPositionsFollowTheNameOnTheWire(t *testing.T) {
	hello := realClientHello(t, "www.front.example.com")
	start, end, host, _ := clientHelloSNI(hello)
	sld := start + len("www.front.example.")
	// example is the second level label: it starts at "example" and midsld is the middle of it
	got := positionsAt(hello, []string{"1", "host", "sld", "midsld", "endhost"}, start, host)
	want := []int{1, start, sld - len("example.") + len("www.front."), 0, end}
	// recompute explicitly instead of trusting the arithmetic above
	sldAt := start + len("www.front.")
	want = []int{1, start, sldAt, sldAt + len("example")/2, end}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("positions = %v, want %v", got, want)
	}
	// with a name that is not in the record only the numeric positions stay
	if got := positionsAt(hello, []string{"1", "host", "midsld"}, -1, ""); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("no host: %v", got)
	}
}

// recorder stands in for a *net.TCPConn: every Write is one intended segment.
type recorder struct {
	mu     sync.Mutex
	writes [][]byte
	nodel  bool
}

func (r *recorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, append([]byte(nil), b...))
	return len(b), nil
}
func (r *recorder) SetNoDelay(v bool) error { r.nodel = v; return nil }
func (r *recorder) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("the recorder has no socket")
}
func (r *recorder) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 443}
}

func TestSendSegmentsSplitAtTheCuts(t *testing.T) {
	hello := realClientHello(t, "front.example.com")
	start, end, host, _ := clientHelloSNI(hello)
	spec, err := parseDesync("split:1,host,endhost")
	if err != nil {
		t.Fatal(err)
	}
	parts := positionsAt(hello, spec.pos, start, host)
	if !reflect.DeepEqual(parts, []int{1, start, end}) {
		t.Fatalf("cuts = %v", parts)
	}
	r := &recorder{}
	if n, err := sendSegments(r, spec.mode, hello, parts); err != nil || n != len(hello) {
		t.Fatalf("sendSegments = %d %v", n, err)
	}
	if !r.nodel {
		t.Error("TCP_NODELAY was not requested, the cuts could merge again")
	}
	var sizes []int
	var joined []byte
	for _, w := range r.writes {
		sizes = append(sizes, len(w))
		joined = append(joined, w...)
	}
	if !reflect.DeepEqual(sizes, []int{1, start - 1, end - start, len(hello) - end}) {
		t.Fatalf("segment sizes = %v", sizes)
	}
	if !bytes.Equal(joined, hello) {
		t.Fatal("the segments do not add up to the ClientHello")
	}
}

func TestDisorderNeedsTTLAndSaysSo(t *testing.T) {
	// the recorder has no socket: a disorder split that cannot lower the TTL of its first segment must fail,
	// not fall back to an ordinary split under the same name
	spec, _ := parseDesync("disorder:1")
	r := &recorder{}
	if _, err := sendSegments(r, spec.mode, []byte("0123456789"), []int{1}); err == nil {
		t.Fatal("disorder without TTL control succeeded")
	}
	if len(r.writes) != 0 {
		t.Fatalf("data was sent anyway: %d writes", len(r.writes))
	}
}

func newTestSession(t *testing.T, address string, port int, quic bool, mods ...func(*ServerOptions)) *serverSession {
	t.Helper()
	o := NewServerOptions()
	o.SetServer("server.example", address, port)
	o.SetQUIC(quic)
	for _, m := range mods {
		m(o)
	}
	s, err := newServerSession(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServerTCPConnCutsOnlyTheClientHello(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := ioReadAll(c)
		got <- b
	}()
	port := l.Addr().(*net.TCPAddr).Port
	sess := newTestSession(t, "127.0.0.1", port, false, func(o *ServerOptions) { o.SetTCPDesync("split:1,midsld") })
	conn, err := sess.dialTCP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hello := realClientHello(t, "front.example.com")
	rest := bytes.Repeat([]byte("after the handshake "), 2000)
	if _, ok := conn.(*serverTCPConn); !ok {
		t.Fatalf("the connection is a %T, not a strategy connection", conn)
	}
	if n, err := conn.Write(hello); err != nil || n != len(hello) {
		t.Fatalf("hello: %d %v", n, err)
	}
	// only the first write is cut up
	if n, err := conn.Write(hello); err != nil || n != len(hello) {
		t.Fatalf("second hello: %d %v", n, err)
	}
	if n, err := conn.Write(rest); err != nil || n != len(rest) {
		t.Fatalf("rest: %d %v", n, err)
	}
	_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	want := append(append(append([]byte{}, hello...), hello...), rest...)
	if b := <-got; !bytes.Equal(b, want) {
		t.Fatalf("the stream changed: %d bytes, want %d", len(b), len(want))
	}
	if sess.splitDials.Load() != 1 || sess.tcpDials.Load() != 1 {
		t.Fatalf("counters: split %d dials %d", sess.splitDials.Load(), sess.tcpDials.Load())
	}
}

func TestServerTCPConnLeavesOtherPayloadsAlone(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := ioReadAll(c)
		got <- b
	}()
	sess := newTestSession(t, "127.0.0.1", l.Addr().(*net.TCPAddr).Port, false, func(o *ServerOptions) { o.SetTCPDesync("split:1") })
	conn, err := sess.dialTCP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// plain HTTP is not a ClientHello: nothing to cut
	payload := []byte("GET / HTTP/1.1\r\nHost: server.example\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	if b := <-got; !bytes.Equal(b, payload) || sess.splitDials.Load() != 0 {
		t.Fatalf("payload %q, splits %d", b, sess.splitDials.Load())
	}
}

func ioReadAll(c net.Conn) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			return out.Bytes(), nil
		}
	}
}

func TestUDPFakesComeFirstFromTheSameSocket(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	type seen struct {
		data []byte
		from string
	}
	got := make(chan seen, 16)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			got <- seen{append([]byte(nil), buf[:n]...), from.String()}
		}
	}()
	port := server.LocalAddr().(*net.UDPAddr).Port
	fake := bytes.Repeat([]byte{0xC0, 0, 0, 0, 1}, 60) // 300 bytes: the shape of a QUIC Initial
	sess := newTestSession(t, "127.0.0.1", port, true, func(o *ServerOptions) {
		o.AddBlob("quic_google", fake)
		o.AddFake("quic_google", 3, 0, 0)
	})
	conn, err := sess.dialUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	real := append([]byte("real handshake"), make([]byte, 40)...)
	if _, err := conn.Write(real); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("second datagram")); err != nil {
		t.Fatal(err)
	}
	var all []seen
	for len(all) < 5 {
		select {
		case s := <-got:
			all = append(all, s)
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d datagrams arrived", len(all))
		}
	}
	for i := 0; i < 3; i++ {
		if !bytes.Equal(all[i].data, fake) {
			t.Fatalf("datagram %d is not a fake", i)
		}
	}
	if !bytes.Equal(all[3].data, real) || string(all[4].data) != "second datagram" {
		t.Fatal("the real datagrams did not follow the fakes in order")
	}
	for _, s := range all {
		if s.from != all[0].from {
			t.Fatalf("a datagram came from another socket: %s and %s", s.from, all[0].from)
		}
	}
	if sess.fakeFlows.Load() != 1 || sess.fakePackets.Load() != 3 {
		t.Fatalf("counters: flows %d packets %d", sess.fakeFlows.Load(), sess.fakePackets.Load())
	}
}

func TestUDPPacketConnPinsTheServerAndSendsFakesOnce(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	got := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			got <- append([]byte(nil), buf[:n]...)
		}
	}()
	fake := bytes.Repeat([]byte{0xC1}, 300)
	sess := newTestSession(t, "127.0.0.1", server.LocalAddr().(*net.UDPAddr).Port, true, func(o *ServerOptions) {
		o.AddBlob("quic_vk", fake)
		o.AddFake("quic_vk", 2, 0, 0)
	})
	pc, dest, err := sess.listenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// whatever address the caller names, the datagram goes to the server
	elsewhere := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 9}
	if _, err := pc.WriteTo([]byte("one"), elsewhere); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("two"), dest); err != nil {
		t.Fatal(err)
	}
	var order []string
	for len(order) < 4 {
		select {
		case b := <-got:
			if bytes.Equal(b, fake) {
				order = append(order, "fake")
			} else {
				order = append(order, string(b))
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("got %v", order)
		}
	}
	if !reflect.DeepEqual(order, []string{"fake", "fake", "one", "two"}) {
		t.Fatalf("order %v", order)
	}
}

func TestTTLFakesFailInsteadOfBeingSentAtTheNormalTTL(t *testing.T) {
	if runtime.GOOS == "windows" {
		// ttl_other.go reports that TTL control is not implemented: exactly the case under test
		server, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		fake := bytes.Repeat([]byte{0xC0}, 300)
		sess := newTestSession(t, "127.0.0.1", server.LocalAddr().(*net.UDPAddr).Port, true, func(o *ServerOptions) {
			o.AddBlob("quic_google", fake)
			o.AddFake("quic_google", 2, 4, 4)
		})
		conn, err := sess.dialUDP(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("real")); err == nil {
			t.Fatal("fakes with a TTL were sent although the TTL cannot be set")
		}
		if sess.lastClass() != errClassTTL {
			t.Fatalf("class %q", sess.lastClass())
		}
		_ = server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, _, err := server.ReadFrom(make([]byte, 2048)); err == nil {
			t.Fatalf("a datagram of %d bytes reached the server", n)
		}
	}
}

func TestSessionRefusesOtherServersAndBadOptions(t *testing.T) {
	sess := newTestSession(t, "203.0.113.9", 443, false)
	for _, c := range []struct {
		host string
		port int
		ok   bool
	}{
		{"server.example", 443, true}, {"SERVER.example", 443, true}, {"203.0.113.9", 443, true},
		{"server.example", 8443, false}, {"other.example", 443, false}, {"203.0.113.10", 443, false},
	} {
		if sess.matches(c.host, c.port) != c.ok {
			t.Errorf("matches(%s, %d) != %v", c.host, c.port, c.ok)
		}
	}
	v6 := newTestSession(t, "2001:db8::9", 443, false)
	if !v6.matches("2001:DB8::9", 443) || v6.matches("2001:db8::a", 443) {
		t.Error("IPv6 comparison")
	}

	bad := []func(*ServerOptions){
		func(o *ServerOptions) { o.SetServer("", "203.0.113.9", 443) },
		func(o *ServerOptions) { o.SetServer("h", "not-an-ip", 443) },
		func(o *ServerOptions) { o.SetServer("h", "203.0.113.9", 0) },
		func(o *ServerOptions) { o.SetTCPDesync("split:1,nonsense") },
		func(o *ServerOptions) { o.SetQUIC(true); o.SetTCPDesync("split:1") },
		func(o *ServerOptions) { o.AddBlob("b", []byte{1}); o.AddFake("b", 1, 0, 0) }, // fakes on a TCP server
		func(o *ServerOptions) { o.SetQUIC(true); o.AddFake("missing", 1, 0, 0) },     // blob not loaded
		func(o *ServerOptions) { o.SetQUIC(true); o.AddBlob("b", []byte{1}); o.AddFake("b", 0, 0, 0) },
		func(o *ServerOptions) { o.SetQUIC(true); o.AddBlob("b", []byte{1}); o.AddFake("b", 1, 300, 0) },
	}
	for i, mod := range bad {
		o := NewServerOptions()
		o.SetServer("server.example", "203.0.113.9", 443)
		mod(o)
		if _, err := newServerSession(o, nil); err == nil {
			t.Errorf("bad options %d accepted", i)
		}
	}
	if _, err := newServerSession(nil, nil); err == nil {
		t.Error("nil options accepted")
	}
}

func TestClassifyErrorGivesClassesNotText(t *testing.T) {
	for text, want := range map[string]string{
		"dial tcp 203.0.113.9:443: connect: connection refused":      errClassRefused,
		"dial tcp 203.0.113.9:443: i/o timeout":                      errClassTimeout,
		"connect: network is unreachable":                            errClassUnreachable,
		"read tcp: connection reset by peer":                         errClassReset,
		"tls: failed to verify certificate: x509: unknown authority": errClassCertificate,
		"tls: server rejected ECH":                                   errClassECH,
		"REALITY: processed invalid connection":                      errClassReality,
		"unexpected status 404":                                      errClassStatus,
		"zarp: ttl cannot be set: operation not permitted":           errClassTTL,
		"VpnService.protect failed":                                  errClassProtect,
		"zarp-dial only dials its own server":                        errClassBlocked,
		"something new":                                              errClassOther,
		"technical failure":                                          errClassOther,
		"mechanical failure":                                         errClassOther,
		"preview protection failure":                                 errClassOther,
		"unreality":                                                  errClassOther,
		"certificateStore failed":                                    errClassOther,
		"thereof":                                                    errClassOther,
	} {
		if got := classifyError(errors.New(text)); got != want {
			t.Errorf("%q is %q, want %q", text, got, want)
		}
	}
	if classifyError(context.DeadlineExceeded) != errClassTimeout || classifyError(nil) != "" {
		t.Error("deadline and nil")
	}
}

func TestTTLProbeAnswers(t *testing.T) {
	// on unix the sockets of the test process can change their TTL; elsewhere the helper says no
	udp, tcp := CanSetUDPTTL(), CanSetTCPTTL()
	if runtime.GOOS == "windows" {
		if udp || tcp {
			t.Fatal("the stubbed platform claims TTL control")
		}
		return
	}
	if !udp || !tcp {
		t.Fatalf("TTL control: udp %v tcp %v", udp, tcp)
	}
}
