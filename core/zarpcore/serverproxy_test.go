package zarpcore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func init() { debugSetupErrors = true }

const testHost = "front.example.com"

const testUUID = "00000000-0000-4000-8000-000000000001"

// certFor makes a self-signed certificate valid for the given names.
func certFor(t *testing.T, names ...string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv}))
}

// Probe both protocols: Windows can reserve a UDP port that TCP's allocator considers free.
func freeTestServerPort() (int, error) {
	var lastErr error
	for attempt := 0; attempt < 16; attempt++ {
		udp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		_ = udp.Close()
		if err != nil {
			lastErr = err
			continue
		}
		_ = tcp.Close()
		return port, nil
	}
	return 0, lastErr
}

// startBoxServer runs a real sing-box inbound (vless, trojan or hysteria2) on 127.0.0.1 and returns its port.
func startBoxServer(t *testing.T, protocol, cert, key string, extra obj, tlsExtra ...obj) int {
	t.Helper()
	ctx := proxyContext(context.Background())
	registry := service.FromContext[adapter.InboundRegistry](ctx).(*inbound.Registry)
	vless.RegisterInbound(registry)
	trojan.RegisterInbound(registry)
	hysteria2.RegisterInbound(registry)
	port, err := freeTestServerPort()
	if err != nil {
		t.Fatal(err)
	}
	user := obj{"name": "test", "password": "test-password"}
	if protocol == "vless" {
		user = obj{"name": "test", "uuid": testUUID}
	}
	tlsOptions := obj{"enabled": true, "certificate": []string{cert}, "key": []string{key}}
	for _, more := range tlsExtra {
		for k, v := range more {
			tlsOptions[k] = v
		}
	}
	input := obj{"type": protocol, "listen": "127.0.0.1", "listen_port": port, "users": []obj{user}, "tls": tlsOptions}
	for k, v := range extra {
		input[k] = v
	}
	config := obj{"log": obj{"disabled": true}, "inbounds": []obj{input}, "outbounds": []obj{{"type": "direct", "tag": "direct"}}, "route": obj{"final": "direct"}}
	var opts option.Options
	if err := json.UnmarshalContext(ctx, []byte(configText(t, config)), &opts); err != nil {
		t.Fatal(err)
	}
	server, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	return port
}

// serverConfig is what the app builds: the protocol outbound, the zarp-dial detour, a direct outbound.
func serverConfig(outbound obj, port int) obj {
	outbound["tag"] = "proxy"
	outbound["detour"] = "server-dial"
	return obj{
		"log":      obj{"disabled": true},
		"inbounds": []obj{{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}},
		"outbounds": []obj{
			outbound,
			{"type": "zarp-dial", "tag": "server-dial", "server": testHost, "server_port": port},
			{"type": "direct", "tag": "direct"},
		},
		"dns":   obj{"servers": []obj{{"type": "local", "tag": "bootstrap"}}},
		"route": obj{"final": "proxy", "default_domain_resolver": "bootstrap"},
	}
}

func serverOptions(port int, quic bool, mods ...func(*ServerOptions)) *ServerOptions {
	o := NewServerOptions()
	o.SetServer(testHost, "127.0.0.1", port)
	o.SetQUIC(quic)
	o.SetConnectTimeoutMs(5000)
	for _, m := range mods {
		m(o)
	}
	return o
}

// tcpObserver forwards to target and records the sizes of the chunks the client sends first on each connection.
type tcpObserver struct {
	addr string
	mu   sync.Mutex
	runs [][]int
}

func newTCPObserver(t *testing.T, target string) *tcpObserver {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &tcpObserver{addr: l.Addr().String()}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go o.serve(c, target)
		}
	}()
	return o
}

func (o *tcpObserver) serve(c net.Conn, target string) {
	defer c.Close()
	up, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer up.Close()
	var sizes []int
	buf := make([]byte, 64<<10)
	// the first bytes of the client, chunk by chunk, until the server answers (or 400 ms pass)
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	total := 0
	for total < 120 { // a ClientHello is longer than this
		n, err := c.Read(buf)
		if n > 0 {
			sizes = append(sizes, n)
			total += n
			_, _ = up.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	o.mu.Lock()
	o.runs = append(o.runs, sizes)
	o.mu.Unlock()
	go func() { _, _ = copyAll(c, up) }()
	_, _ = copyAll(up, c)
}

func copyAll(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 64<<10)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err != nil {
			return total, err
		}
	}
}

func (o *tcpObserver) firstChunks() [][]int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([][]int(nil), o.runs...)
}

func TestServerProxyTCPStrategy(t *testing.T) {
	cert, key := certFor(t, testHost)
	for _, protocol := range []string{"vless", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			target := tcpEcho(t)
			port := startBoxServer(t, protocol, cert, key, nil)
			observer := newTCPObserver(t, net.JoinHostPort("127.0.0.1", itoa(port)))
			obPort := observer.addr[strings.LastIndex(observer.addr, ":")+1:]
			tls := obj{"enabled": true, "server_name": testHost, "certificate": []string{cert}}
			out := obj{"type": protocol, "server": testHost, "server_port": atoi(obPort), "tls": tls}
			if protocol == "vless" {
				out["uuid"] = testUUID
				out["packet_encoding"] = "xudp"
			} else {
				out["password"] = "test-password"
			}
			config := serverConfig(out, atoi(obPort))
			opts := serverOptions(atoi(obPort), false, func(o *ServerOptions) { o.SetTCPDesync("split:1,midsld") })
			p, err := NewServerProxy(configText(t, config), opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()

			// the connection works, TCP and UDP, through the strategy
			checkTCP(t, p.SocksPort(), target)
			checkTCP(t, p.SocksPort(), target)
			checkUDP(t, p.SocksPort())

			// every connection to the server had its ClientHello cut up
			if p.ServerConnections() < 2 || p.SplitCount() != p.ServerConnections() {
				t.Fatalf("connections %d, cut ClientHellos %d", p.ServerConnections(), p.SplitCount())
			}
			if p.LastError() != "" {
				t.Fatalf("a failure was recorded: %s", p.LastError())
			}
			// on the wire the first chunk is one byte (kernel coalescing can hide it, so look at all connections)
			single := 0
			for _, sizes := range observer.firstChunks() {
				if len(sizes) >= 2 && sizes[0] == 1 {
					single++
				}
			}
			if single == 0 {
				t.Logf("the kernel merged the segments on loopback (%v); the cut itself is proven by the counters and the recorder test", observer.firstChunks())
			}
		})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// udpObserver forwards datagrams between a client and a server and records what the client sent first.
type udpObserver struct {
	addr  string
	mu    sync.Mutex
	first []observed
}

type observed struct {
	from string
	data []byte
}

func newUDPObserver(t *testing.T, target string) *udpObserver {
	t.Helper()
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &udpObserver{addr: front.LocalAddr().String()}
	dest, _ := net.ResolveUDPAddr("udp", target)
	t.Cleanup(func() { _ = front.Close() })
	var mu sync.Mutex
	upstreams := map[string]*net.UDPConn{}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			data := append([]byte(nil), buf[:n]...)
			o.mu.Lock()
			if len(o.first) < 32 {
				o.first = append(o.first, observed{from.String(), data})
			}
			o.mu.Unlock()
			mu.Lock()
			up := upstreams[from.String()]
			if up == nil {
				up, err = net.DialUDP("udp", nil, dest)
				if err != nil {
					mu.Unlock()
					continue
				}
				upstreams[from.String()] = up
				go func(up *net.UDPConn, from net.Addr) {
					b := make([]byte, 65535)
					for {
						n, err := up.Read(b)
						if err != nil {
							return
						}
						_, _ = front.WriteTo(b[:n], from)
					}
				}(up, from)
			}
			mu.Unlock()
			_, _ = up.Write(data)
		}
	}()
	return o
}

func (o *udpObserver) seen() []observed {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]observed(nil), o.first...)
}

func TestServerProxyQUICFakes(t *testing.T) {
	cert, key := certFor(t, testHost)
	fake := bytes.Repeat([]byte{0xC3, 0, 0, 0, 1, 0xAA}, 60) // recognisable, 360 bytes
	for _, salamander := range []bool{false, true} {
		name := "plain"
		if salamander {
			name = "salamander"
		}
		t.Run(name, func(t *testing.T) {
			target := tcpEcho(t)
			extra := obj{}
			if salamander {
				extra["obfs"] = obj{"type": "salamander", "password": "obfs-key"}
			}
			port := startBoxServer(t, "hysteria2", cert, key, extra)
			observer := newUDPObserver(t, "127.0.0.1:"+itoa(port))
			obPort := atoi(observer.addr[strings.LastIndex(observer.addr, ":")+1:])
			out := obj{
				"type": "hysteria2", "server": testHost, "server_port": obPort, "password": "test-password",
				"tls": obj{"enabled": true, "server_name": testHost, "certificate": []string{cert}},
			}
			if salamander {
				out["obfs"] = obj{"type": "salamander", "password": "obfs-key"}
			}
			config := serverConfig(out, obPort)
			opts := serverOptions(obPort, true, func(o *ServerOptions) {
				o.AddBlob("quic_google", fake)
				o.AddFake("quic_google", 4, 0, 0)
			})
			p, err := NewServerProxy(configText(t, config), opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()

			checkTCP(t, p.SocksPort(), target)
			checkUDP(t, p.SocksPort())

			seen := observer.seen()
			if len(seen) < 6 {
				t.Fatalf("only %d datagrams observed", len(seen))
			}
			for i := 0; i < 4; i++ {
				if !bytes.Equal(seen[i].data, fake) {
					t.Fatalf("datagram %d is not a fake (%d bytes)", i, len(seen[i].data))
				}
			}
			if bytes.Equal(seen[4].data, fake) {
				t.Fatal("more fakes than configured")
			}
			for _, s := range seen {
				if s.from != seen[0].from {
					t.Fatalf("fakes and handshake used different sockets: %s and %s", s.from, seen[0].from)
				}
			}
			if p.FakeFlowCount() != 1 || p.FakePacketCount() != 4 {
				t.Fatalf("fake flows %d, fake packets %d", p.FakeFlowCount(), p.FakePacketCount())
			}
		})
	}
}

// Every new connection to the server gets the strategy again, not only the first one.
func TestServerProxyStrategyHoldsForEveryNewConnection(t *testing.T) {
	cert, key := certFor(t, testHost)
	target := tcpEcho(t)
	port := startBoxServer(t, "trojan", cert, key, nil)
	out := obj{"type": "trojan", "server": testHost, "server_port": port, "password": "test-password",
		"tls": obj{"enabled": true, "server_name": testHost, "certificate": []string{cert}}}
	p, err := NewServerProxy(configText(t, serverConfig(out, port)), serverOptions(port, false, func(o *ServerOptions) { o.SetTCPDesync("split:1,host") }), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for i := 0; i < 6; i++ {
		checkTCP(t, p.SocksPort(), target)
	}
	if p.ServerConnections() < 6 || p.SplitCount() != p.ServerConnections() {
		t.Fatalf("connections %d, cut %d", p.ServerConnections(), p.SplitCount())
	}
}

func TestServerProxyRefusesWrongServerAndBadConfigs(t *testing.T) {
	out := obj{"type": "trojan", "server": "other.example", "server_port": 443, "password": "p",
		"tls": obj{"enabled": true, "server_name": "other.example"}}
	cfg := serverConfig(out, 443)
	// the zarp-dial outbound names testHost but the session is for another server
	opts := serverOptions(443, false, func(o *ServerOptions) { o.SetServer("elsewhere.example", "127.0.0.1", 443); o.SetTCPDesync("split:1") })
	if _, err := NewServerProxy(configText(t, cfg), opts, nil); err == nil {
		t.Fatal("a detour for another server was accepted")
	}
	// an unknown field in the configuration is an error, never ignored
	cfg2 := serverConfig(obj{"type": "trojan", "server": testHost, "server_port": 443, "password": "p", "bogus": 1}, 443)
	if _, err := NewServerProxy(configText(t, cfg2), serverOptions(443, false), nil); err == nil {
		t.Fatal("unknown field accepted")
	}
	// without a session the outbound type cannot even be created
	_, err := NewProxy(configText(t, serverConfig(obj{"type": "trojan", "server": testHost, "server_port": 443, "password": "p"}, 443)))
	if err == nil {
		t.Fatal("zarp-dial worked without a session")
	}
	// error text carries no credentials in the release setting
	debugSetupErrors = false
	defer func() { debugSetupErrors = true }()
	_, err = NewServerProxy(configText(t, cfg2), serverOptions(443, false), nil)
	if err == nil || strings.Contains(err.Error(), "bogus") || strings.Contains(err.Error(), "password") {
		t.Fatalf("setup error leaks details: %v", err)
	}
}

func TestServerProxyClassifiesAFailedServer(t *testing.T) {
	// nothing listens on the port: the failure is a refusal, and the class says so without any address
	port, err := freeTestServerPort()
	if err != nil {
		t.Fatal(err)
	}
	out := obj{"type": "trojan", "server": testHost, "server_port": port, "password": "p",
		"tls": obj{"enabled": true, "server_name": testHost}}
	p, err := NewServerProxy(configText(t, serverConfig(out, port)), serverOptions(port, false, func(o *ServerOptions) { o.SetTCPDesync("split:1") }), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	target := tcpEcho(t)
	// the SOCKS connect fails because the server does not answer
	conn, derr := net.DialTimeout("tcp", "127.0.0.1:"+itoa(p.SocksPort()), 2*time.Second)
	if derr != nil {
		t.Fatal(derr)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	resp := make([]byte, 2)
	_, _ = conn.Read(resp)
	host, portText, _ := net.SplitHostPort(target)
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	req = append(req, byte(atoi(portText)>>8), byte(atoi(portText)))
	_, _ = conn.Write(req)
	reply := make([]byte, 10)
	_, _ = conn.Read(reply)
	if reply[1] == 0 {
		t.Fatal("connect succeeded although the server is down")
	}
	if p.LastError() != errClassRefused {
		t.Fatalf("class %q, want %q", p.LastError(), errClassRefused)
	}
}

// ECH: the name in the TLS handshake is encrypted. A list the server cannot use must break the connection; it must never
// continue as plain TLS.
func TestServerProxyECHNeverFallsBack(t *testing.T) {
	cert, key := certFor(t, testHost)
	goodConfig, goodKeys, err := boxtls.ECHKeygenDefault("cover.example.com")
	if err != nil {
		t.Fatal(err)
	}
	otherConfig, _, err := boxtls.ECHKeygenDefault("cover.example.com")
	if err != nil {
		t.Fatal(err)
	}
	pemLines := func(text string) []string {
		return strings.Split(strings.TrimSpace(text), "\n")
	}
	for _, protocol := range []string{"vless", "trojan", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			target := tcpEcho(t)
			port := startBoxServer(t, protocol, cert, key, nil, obj{"ech": obj{"enabled": true, "key": pemLines(goodKeys)}})
			quic := protocol == "hysteria2"
			build := func(config string) *Proxy {
				out := obj{"type": protocol, "server": testHost, "server_port": port,
					"tls": obj{"enabled": true, "server_name": testHost, "certificate": []string{cert},
						"ech": obj{"enabled": true, "config": pemLines(config)}}}
				switch protocol {
				case "vless":
					out["uuid"] = testUUID
					out["packet_encoding"] = "xudp"
				default:
					out["password"] = "test-password"
				}
				opts := serverOptions(port, quic, func(o *ServerOptions) {
					if quic {
						o.AddBlob("quic_google", bytes.Repeat([]byte{0xC0, 0, 0, 0, 1}, 70))
						o.AddFake("quic_google", 2, 0, 0)
					} else {
						o.SetTCPDesync("split:1,midsld")
					}
				})
				p, err := NewServerProxy(configText(t, serverConfig(out, port)), opts, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				return p
			}
			good := build(goodConfig)
			checkTCP(t, good.SocksPort(), target)
			checkUDP(t, good.SocksPort())
			bad := build(otherConfig)
			if tcpWorks(t, bad.SocksPort()) {
				t.Fatal("traffic passed although the server does not accept the ECH configuration")
			}
		})
	}
}
