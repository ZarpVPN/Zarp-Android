package zarpcore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	stdjson "encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/proxy"
)

type obj = map[string]any

func configText(t *testing.T, value any) string {
	t.Helper()
	data, err := stdjson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func localProxyConfig(outbound obj, rules []obj) obj {
	return obj{
		"log":       obj{"disabled": true},
		"inbounds":  []obj{{"type": "socks", "listen": "127.0.0.1", "listen_port": 0}},
		"outbounds": []obj{outbound, {"type": "direct", "tag": "direct"}},
		"dns":       obj{"servers": []obj{{"type": "local", "tag": "bootstrap"}}},
		"route":     obj{"final": "proxy", "default_domain_resolver": "bootstrap", "rules": rules},
	}
}

func tcpEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String()
}

func checkTCP(t *testing.T, port int, target string) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := "zarp-local-proxy-test"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != payload {
		t.Fatalf("unexpected reply: %q", reply)
	}
}

// Like hev, the UDP source port differs from the SOCKS TCP control port.
func checkUDP(t *testing.T, port int) {
	t.Helper()
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		n, peer, e := echo.ReadFrom(b)
		if e == nil {
			_, _ = echo.WriteTo(b[:n], peer)
		}
	}()
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = control.Write([]byte{5, 1, 0})
	response := make([]byte, 2)
	if _, err := io.ReadFull(control, response); err != nil {
		t.Fatal(err)
	}
	_, _ = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	header := make([]byte, 4)
	if _, err := io.ReadFull(control, header); err != nil {
		t.Fatal(err)
	}
	if header[1] != 0 {
		t.Fatalf("UDP associate failed: %v", header)
	}
	addressSize := 4
	if header[3] == 4 {
		addressSize = 16
	}
	address := make([]byte, addressSize+2)
	if _, err := io.ReadFull(control, address); err != nil {
		t.Fatal(err)
	}
	relay := &net.UDPAddr{IP: net.IP(address[:addressSize]), Port: int(binary.BigEndian.Uint16(address[addressSize:]))}
	if relay.IP.IsUnspecified() {
		relay.IP = net.ParseIP("127.0.0.1")
	}
	udp, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
	target := echo.LocalAddr().(*net.UDPAddr)
	request := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(target.Port >> 8), byte(target.Port), 'z', 'a', 'r', 'p'}
	if _, err := udp.Write(request); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 512)
	n, err := udp.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 || string(data[n-4:n]) != "zarp" {
		t.Fatalf("bad UDP reply: %x", data[:n])
	}
}

func TestProxyRouting(t *testing.T) {
	target := tcpEcho(t)
	broken := obj{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1, "connect_timeout": "1s"}
	for _, rule := range []obj{{"ip_cidr": []string{"127.0.0.0/8"}, "outbound": "direct"}, {"ip_is_private": true, "outbound": "direct"}} {
		p, err := NewProxy(configText(t, localProxyConfig(broken, []obj{rule})))
		if err != nil {
			t.Fatal(err)
		}
		checkTCP(t, p.SocksPort(), target)
		checkUDP(t, p.SocksPort())
		p.Close()
		p.Close()
	}
	p, err := NewProxy(configText(t, localProxyConfig(broken, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	dialer, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", p.SocksPort()), nil, &net.Dialer{Timeout: time.Second})
	if conn, err := dialer.Dial("tcp", target); err == nil {
		conn.Close()
		t.Fatal("unmatched traffic bypassed the proxy")
	}
}

func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv}))
}

func TestProxyProtocols(t *testing.T) {
	target := tcpEcho(t)
	cert, key := testCertificate(t)
	const uuid = "00000000-0000-4000-8000-000000000001"
	for _, protocol := range []string{"vless", "trojan", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
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
				user = obj{"name": "test", "uuid": uuid}
			}
			input := obj{"type": protocol, "listen": "127.0.0.1", "listen_port": port, "users": []obj{user}, "tls": obj{"enabled": true, "certificate": []string{cert}, "key": []string{key}}}
			config := obj{"log": obj{"disabled": true}, "inbounds": []obj{input}, "outbounds": []obj{{"type": "direct", "tag": "direct"}}, "route": obj{"final": "direct"}}
			var opts option.Options
			if err := json.UnmarshalContext(ctx, []byte(configText(t, config)), &opts); err != nil {
				t.Fatal(err)
			}
			server, err := box.New(box.Options{Context: ctx, Options: opts})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if err := server.Start(); err != nil {
				t.Fatal(err)
			}
			output := obj{"type": protocol, "tag": "proxy", "server": "127.0.0.1", "server_port": port, "tls": obj{"enabled": true, "server_name": "localhost", "certificate": []string{cert}}}
			if protocol == "vless" {
				output["uuid"] = uuid
				output["packet_encoding"] = "xudp"
			} else {
				output["password"] = "test-password"
			}
			p, err := NewProxy(configText(t, localProxyConfig(output, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			checkTCP(t, p.SocksPort(), target)
			checkUDP(t, p.SocksPort())
		})
	}
}

func TestCountryAssets(t *testing.T) {
	for _, country := range []string{"ru", "ir", "cn"} {
		path := filepath.Join("..", "..", "app", "src", "main", "assets", "routes", country+".txt")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		v4, v6 := 0, 0
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			prefix, err := netip.ParsePrefix(line)
			if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
				t.Fatalf("invalid country prefix %s: %v", line, err)
			}
			if prefix.Addr().Is4() {
				v4++
			} else {
				v6++
			}
		}
		if v4 < 100 || v6 < 10 {
			t.Fatalf("incomplete %s: v4=%d v6=%d", country, v4, v6)
		}
	}
}
