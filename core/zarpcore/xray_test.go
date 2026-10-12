package zarpcore

// Real traffic through the XHTTP bridge: the official Xray release runs as a throwaway server on localhost
// (set ZARP_TEST_XRAY to its path; the tests skip when it is missing), the in-process Xray client and sing-box
// carry TCP and UDP through it. Nothing here touches the network beyond 127.0.0.1.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func xrayExe(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("ZARP_TEST_XRAY"), `D:\zarp-dev\tools\xray-26.9.30-windows\bin\xray.exe`}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("set ZARP_TEST_XRAY to the official Xray 26.9.30 binary to run the XHTTP tests")
	return ""
}

type xrayServer struct {
	exe  string
	dir  string
	port int
	out  *bytes.Buffer
}

func (x *xrayServer) logs() string { return x.out.String() }

// xrayRun runs the xray tool with arguments and returns its output.
func xrayRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(xrayExe(t), args...).CombinedOutput()
	if err != nil {
		t.Fatalf("xray %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func field(output, name string) string {
	lines := strings.Split(strings.ReplaceAll(output, "\r", ""), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, name) {
			rest := strings.TrimSpace(strings.TrimPrefix(l, name))
			rest = strings.TrimPrefix(rest, ":")
			if rest = strings.TrimSpace(rest); rest != "" {
				return rest
			}
			if i+1 < len(lines) {
				return strings.TrimSpace(lines[i+1])
			}
		}
	}
	return ""
}

// startXrayServer runs a VLESS inbound with the given stream settings; udp makes the server listen for QUIC too.
func startXrayServer(t *testing.T, stream obj) *xrayServer {
	t.Helper()
	exe := xrayExe(t)
	port, err := freeTestServerPort()
	if err != nil {
		t.Fatal(err)
	}
	config := obj{
		"log": obj{"loglevel": "warning"},
		"inbounds": []obj{{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings":       obj{"clients": []obj{{"id": testUUID}}, "decryption": "none"},
			"streamSettings": stream,
		}},
		// recent Xray blocks private destinations by default; the echo server is on loopback
		"outbounds": []obj{{"protocol": "freedom", "settings": obj{"finalRules": []obj{{"action": "allow", "ip": []string{"127.0.0.1"}}}}}},
	}
	dir := t.TempDir()
	data, _ := json.Marshal(config)
	file := filepath.Join(dir, "server.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "run", "-c", file)
	cmd.Dir = dir
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(out.String(), "started") {
		if time.Now().After(deadline) || cmd.ProcessState != nil {
			t.Fatalf("xray did not start:\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return &xrayServer{exe: exe, dir: dir, port: port, out: out}
}

// writeCert writes a certificate valid for testHost and returns the files and the pin (SHA-256 of the DER).
func writeCert(t *testing.T) (certFile, keyFile, pin string) {
	t.Helper()
	cert, key := certFor(t, testHost)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, []byte(cert), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(cert))
	sum := sha256.Sum256(block.Bytes)
	return certFile, keyFile, hex.EncodeToString(sum[:])
}

// xhttpClientConfig is the sing-box configuration of an XHTTP server: a placeholder SOCKS outbound for the bridge.
func xhttpClientConfig() obj {
	return obj{
		"log":      obj{"disabled": true},
		"inbounds": []obj{{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}},
		"outbounds": []obj{
			{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1, "version": "5"},
			{"type": "direct", "tag": "direct"},
		},
		"dns":   obj{"servers": []obj{{"type": "local", "tag": "bootstrap"}}},
		"route": obj{"final": "proxy", "default_domain_resolver": "bootstrap"},
	}
}

// xrayOutbound is what the app builds from an XHTTP link.
func xrayOutbound(port int, stream obj) string { return xrayOutboundAt(testHost, port, stream) }

func xrayOutboundAt(address string, port int, stream obj) string {
	data, _ := json.Marshal(obj{
		"tag": "server", "protocol": "vless",
		"settings": obj{"vnext": []obj{{
			"address": address, "port": port,
			"users": []obj{{"id": testUUID, "encryption": "none", "flow": ""}},
		}}},
		"streamSettings": stream,
	})
	return string(data)
}

func startXhttpProxy(t *testing.T, port int, quic bool, stream obj, mods ...func(*ServerOptions)) *Proxy {
	t.Helper()
	opts := serverOptions(port, quic, func(o *ServerOptions) { o.SetXrayOutbound(xrayOutbound(port, stream)) })
	for _, m := range mods {
		m(opts)
	}
	p, err := NewServerProxy(configText(t, xhttpClientConfig()), opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// expectTraffic sends TCP and UDP through the proxy.
func expectTraffic(t *testing.T, p *Proxy) {
	t.Helper()
	target := tcpEcho(t)
	checkTCP(t, p.SocksPort(), target)
	checkTCP(t, p.SocksPort(), target)
	checkUDP(t, p.SocksPort())
}

func TestXhttpPlainEveryMode(t *testing.T) {
	xrayExe(t)
	for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			srv := startXrayServer(t, obj{"network": "xhttp", "security": "none", "xhttpSettings": obj{"path": "/xh", "mode": "auto"}})
			// Xray 26.x refuses VLESS without TLS unless the server address is private
			stream := obj{
				"network": "xhttp", "security": "none",
				"xhttpSettings": obj{"path": "/xh", "mode": mode, "host": testHost},
			}
			opts := serverOptions(srv.port, false, func(o *ServerOptions) {
				o.SetServer("127.0.0.1", "127.0.0.1", srv.port)
				o.SetXrayOutbound(xrayOutboundAt("127.0.0.1", srv.port, stream))
			})
			p, err := NewServerProxy(configText(t, xhttpClientConfig()), opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			expectTraffic(t, p)
			if p.ServerConnections() == 0 {
				t.Fatal("nothing connected to the server")
			}
		})
	}
}

func TestXhttpTLSPinnedWithSplit(t *testing.T) {
	xrayExe(t)
	certFile, keyFile, pin := writeCert(t)
	srv := startXrayServer(t, obj{
		"network": "xhttp", "security": "tls",
		"tlsSettings":   obj{"certificates": []obj{{"certificateFile": certFile, "keyFile": keyFile}}, "alpn": []string{"h2", "http/1.1"}},
		"xhttpSettings": obj{"path": "/xh"},
	})
	stream := func(pin string) obj {
		return obj{
			"network": "xhttp", "security": "tls",
			"tlsSettings":   obj{"serverName": testHost, "pinnedPeerCertSha256": pin, "fingerprint": "chrome"},
			"xhttpSettings": obj{"path": "/xh", "mode": "packet-up"},
		}
	}
	p := startXhttpProxy(t, srv.port, false, stream(pin), func(o *ServerOptions) { o.SetTCPDesync("split:1,midsld") })
	expectTraffic(t, p)
	// every TCP connection of Xray to the server had its ClientHello cut up, whatever stream or mux opened it
	if p.ServerConnections() < 1 || p.SplitCount() != p.ServerConnections() {
		t.Fatalf("connections %d, cut ClientHellos %d\n%s", p.ServerConnections(), p.SplitCount(), srv.logs())
	}
	if p.ForeignConnections() != 0 {
		t.Fatalf("%d connections went to other addresses", p.ForeignConnections())
	}

	// a wrong pin is a failure, never a silent success
	wrong := strings.Repeat("ab", 32)
	bad := startXhttpProxy(t, srv.port, false, stream(wrong), func(o *ServerOptions) { o.SetTCPDesync("split:1") })
	if tcpWorks(t, bad.SocksPort()) {
		t.Fatal("traffic passed with a wrong certificate pin")
	}
}

// tcpWorks reports whether an echo through the proxy succeeds.
func tcpWorks(t *testing.T, port int) bool {
	t.Helper()
	target := tcpEcho(t)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return false
	}
	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return false
	}
	host, portText, _ := net.SplitHostPort(target)
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	req = append(req, byte(atoi(portText)>>8), byte(atoi(portText)))
	if _, err := conn.Write(req); err != nil {
		return false
	}
	reply := make([]byte, 10)
	if _, err := conn.Read(reply); err != nil || reply[1] != 0 {
		return false
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return false
	}
	buf := make([]byte, 4)
	_, err = conn.Read(buf)
	return err == nil && string(buf) == "ping"
}

func TestXhttpOverQUICWithFakes(t *testing.T) {
	xrayExe(t)
	certFile, keyFile, pin := writeCert(t)
	srv := startXrayServer(t, obj{
		"network": "xhttp", "security": "tls",
		"tlsSettings":   obj{"certificates": []obj{{"certificateFile": certFile, "keyFile": keyFile}}, "alpn": []string{"h3"}},
		"xhttpSettings": obj{"path": "/xh"},
	})
	fake := bytes.Repeat([]byte{0xC2, 0, 0, 0, 1, 0x55}, 60)
	stream := obj{
		"network": "xhttp", "security": "tls",
		"tlsSettings":   obj{"serverName": testHost, "alpn": []string{"h3"}, "pinnedPeerCertSha256": pin},
		"xhttpSettings": obj{"path": "/xh", "mode": "packet-up"},
	}
	p := startXhttpProxy(t, srv.port, true, stream, func(o *ServerOptions) {
		o.AddBlob("quic_google", fake)
		o.AddFake("quic_google", 3, 0, 0)
	})
	expectTraffic(t, p)
	if p.FakeFlowCount() < 1 || p.FakePacketCount() != 3*p.FakeFlowCount() {
		t.Fatalf("fake flows %d, packets %d\n%s", p.FakeFlowCount(), p.FakePacketCount(), srv.logs())
	}
	if p.ForeignConnections() != 0 {
		t.Fatalf("%d connections went to other addresses", p.ForeignConnections())
	}
}

func TestXhttpReality(t *testing.T) {
	xrayExe(t)
	keys := xrayRun(t, "x25519")
	private, public := field(keys, "PrivateKey"), field(keys, "Password (PublicKey)")
	if private == "" || public == "" {
		t.Fatalf("cannot read the keys:\n%s", keys)
	}
	// the site Reality imitates: a TLS 1.3 server with a certificate for the name
	cert, key := certFor(t, testHost)
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	site, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = site.Close() })
	go func() {
		for {
			c, err := site.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	srv := startXrayServer(t, obj{
		"network": "xhttp", "security": "reality",
		"realitySettings": obj{
			"dest": site.Addr().String(), "serverNames": []string{testHost}, "privateKey": private, "shortIds": []string{"0123abcd"},
		},
		"xhttpSettings": obj{"path": "/xh"},
	})
	stream := obj{
		"network": "xhttp", "security": "reality",
		"realitySettings": obj{"serverName": testHost, "fingerprint": "chrome", "publicKey": public, "shortId": "0123abcd", "spiderX": "/"},
		"xhttpSettings":   obj{"path": "/xh", "mode": "stream-one"},
	}
	p := startXhttpProxy(t, srv.port, false, stream, func(o *ServerOptions) { o.SetTCPDesync("split:1,midsld") })
	expectTraffic(t, p)
	if p.SplitCount() < 1 || p.SplitCount() != p.ServerConnections() {
		t.Fatalf("connections %d, cut ClientHellos %d\n%s", p.ServerConnections(), p.SplitCount(), srv.logs())
	}
	// a wrong public key must not connect
	wrong := strings.Replace(stream["realitySettings"].(obj)["publicKey"].(string), public[:3], "AAA", 1)
	bad := obj{"network": "xhttp", "security": "reality",
		"realitySettings": obj{"serverName": testHost, "fingerprint": "chrome", "publicKey": wrong, "shortId": "0123abcd"},
		"xhttpSettings":   obj{"path": "/xh"}}
	if wrong != public {
		pb := startXhttpProxy(t, srv.port, false, bad)
		if tcpWorks(t, pb.SocksPort()) {
			t.Fatal("traffic passed with a wrong Reality key")
		}
	}
}

func TestXhttpECHNeverFallsBackToPlainTLS(t *testing.T) {
	xrayExe(t)
	certFile, keyFile, pin := writeCert(t)
	ech := xrayRun(t, "tls", "ech", "--serverName", testHost)
	list, keys := field(ech, "ECH config list"), field(ech, "ECH server keys")
	if list == "" || keys == "" {
		t.Fatalf("cannot read the ECH output:\n%s", ech)
	}
	srv := startXrayServer(t, obj{
		"network": "xhttp", "security": "tls",
		"tlsSettings":   obj{"certificates": []obj{{"certificateFile": certFile, "keyFile": keyFile}}, "echServerKeys": keys, "alpn": []string{"h2"}},
		"xhttpSettings": obj{"path": "/xh"},
	})
	stream := func(list string) obj {
		return obj{
			"network": "xhttp", "security": "tls",
			"tlsSettings":   obj{"serverName": testHost, "pinnedPeerCertSha256": pin, "echConfigList": list, "alpn": []string{"h2"}},
			"xhttpSettings": obj{"path": "/xh", "mode": "packet-up"},
		}
	}
	good := startXhttpProxy(t, srv.port, false, stream(list), func(o *ServerOptions) { o.SetTCPDesync("split:1") })
	expectTraffic(t, good)

	// a list the server cannot decrypt: the connection must fail, not continue with the plain name
	other := xrayRun(t, "tls", "ech", "--serverName", testHost)
	wrong := field(other, "ECH config list")
	if wrong == list {
		t.Fatal("two ECH configurations are identical")
	}
	bad := startXhttpProxy(t, srv.port, false, stream(wrong), func(o *ServerOptions) { o.SetTCPDesync("split:1") })
	if tcpWorks(t, bad.SocksPort()) {
		t.Fatal("traffic passed although the server does not accept the ECH configuration")
	}
}

func TestXhttpExtraSettingsReachXray(t *testing.T) {
	xrayExe(t)
	certFile, keyFile, pin := writeCert(t)
	srv := startXrayServer(t, obj{
		"network": "xhttp", "security": "tls",
		"tlsSettings":   obj{"certificates": []obj{{"certificateFile": certFile, "keyFile": keyFile}}, "alpn": []string{"h2"}},
		"xhttpSettings": obj{"path": "/xh"},
	})
	tlsOf := obj{"serverName": testHost, "pinnedPeerCertSha256": pin, "alpn": []string{"h2"}}
	extra := obj{
		"xPaddingBytes": "100-300",
		"xmux":          obj{"maxConcurrency": "2-4", "hMaxRequestTimes": "50-90", "hMaxReusableSecs": "100-200"},
		"headers":       obj{"X-Zarp-Test": "1"},
	}
	p := startXhttpProxy(t, srv.port, false, obj{
		"network": "xhttp", "security": "tls", "tlsSettings": tlsOf,
		"xhttpSettings": obj{"path": "/xh", "mode": "packet-up", "host": testHost, "extra": extra},
	}, func(o *ServerOptions) { o.SetTCPDesync("split:1") })
	expectTraffic(t, p)
	if p.SplitCount() != p.ServerConnections() {
		t.Fatalf("connections %d, cut %d", p.ServerConnections(), p.SplitCount())
	}

	// settings Xray rejects stop the bridge with a short reason that holds no values
	o := serverOptions(srv.port, false, func(o *ServerOptions) {
		o.SetXrayOutbound(xrayOutbound(srv.port, obj{"network": "xhttp", "security": "tls", "tlsSettings": tlsOf, "xhttpSettings": obj{"mode": "sideways"}}))
	})
	if _, err := NewServerProxy(configText(t, xhttpClientConfig()), o, nil); err == nil {
		t.Fatal("an unknown XHTTP mode was accepted")
	} else if !strings.HasPrefix(err.Error(), "xray:") || strings.Contains(err.Error(), testUUID) || strings.Contains(err.Error(), pin) {
		t.Fatalf("unexpected error text: %v", err)
	}
}

func TestXhttpDownloadAddressIsNotCoveredAndSaysSo(t *testing.T) {
	xrayExe(t)
	certFile, keyFile, pin := writeCert(t)
	srv := startXrayServer(t, obj{
		"network": "xhttp", "security": "tls",
		"tlsSettings":   obj{"certificates": []obj{{"certificateFile": certFile, "keyFile": keyFile}}, "alpn": []string{"h2"}},
		"xhttpSettings": obj{"path": "/xh"},
	})
	tlsOf := obj{"serverName": testHost, "pinnedPeerCertSha256": pin, "alpn": []string{"h2"}}
	// the download half is reached under another name ("localhost" is the same server): the strategy belongs to the
	// main server only, and the app has to be able to say that the download connection is not covered
	extra := obj{"downloadSettings": obj{
		"address": "localhost", "port": srv.port, "network": "xhttp", "security": "tls",
		"tlsSettings": tlsOf, "xhttpSettings": obj{"path": "/xh", "mode": "stream-up"},
	}}
	p := startXhttpProxy(t, srv.port, false, obj{
		"network": "xhttp", "security": "tls", "tlsSettings": tlsOf,
		"xhttpSettings": obj{"path": "/xh", "mode": "auto", "extra": extra},
	}, func(o *ServerOptions) { o.SetTCPDesync("split:1") })
	expectTraffic(t, p)
	if p.ForeignConnections() < 1 {
		t.Fatalf("the download connection was not counted as foreign (server connections %d)\n%s", p.ServerConnections(), srv.logs())
	}
	if p.SplitCount() != p.ServerConnections() || p.ServerConnections() < 1 {
		t.Fatalf("the strategy did not stay on the main server: cut %d of %d", p.SplitCount(), p.ServerConnections())
	}
}
