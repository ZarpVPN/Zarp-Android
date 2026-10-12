package zarpcore

// Manual adb harness. No saved app state is changed. Runtime LAN addresses are
// written only to private throwaway configuration files, never to output.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	boxjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func TestDeviceVerificationServer(t *testing.T) {
	dir := os.Getenv("ZARP_DEVICE_TEST_DIR")
	if dir == "" {
		t.Skip("manual adb harness: set ZARP_DEVICE_TEST_DIR to an ignored build directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	addresses, _ := net.InterfaceAddrs()
	ips := []net.IP{net.ParseIP("192.0.2.20"), net.ParseIP("198.51.100.20"), net.ParseIP("127.0.0.1")}
	lan := os.Getenv("ZARP_DEVICE_TEST_HOST")
	for _, address := range addresses {
		ip := net.ParseIP(strings.Split(address.String(), "/")[0])
		if ip != nil && ip.To4() != nil {
			ips = append(ips, ip)
			if lan == "" && ip.IsPrivate() && !ip.IsLoopback() {
				lan = ip.String()
			}
		}
	}
	if net.ParseIP(lan) == nil {
		t.Fatal("a local LAN address is required for direct and UDP phone checks")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(17), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"proxy.example.com", "probe.example.com"}, IPAddresses: ips,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalECPrivateKey(key)
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	pair, err := tls.X509KeyPair([]byte(cert), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "0.0.0.0:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	httpsPort := listener.Addr().(*net.TCPAddr).Port
	var requests, directRequests atomic.Int64
	httpServer := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if strings.HasPrefix(r.URL.Path, "/direct") {
			directRequests.Add(1)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len("ip=192.0.2.1\nwarp=off\nverification=ok\n")))
		_, _ = w.Write([]byte("ip=192.0.2.1\nwarp=off\nverification=ok\n"))
	})}
	go func() { _ = httpServer.Serve(listener) }()
	t.Cleanup(func() { _ = httpServer.Close() })
	certFile, keyFile := filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "private.pem")
	_ = os.WriteFile(certFile, []byte(cert), 0600)
	_ = os.WriteFile(keyFile, []byte(keyPEM), 0600)
	pin := sha256.Sum256(der)
	xrayPort, err := freeTestServerPort()
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := obj{
		"log": obj{"loglevel": "none"},
		"inbounds": []obj{{
			"listen": "127.0.0.1", "port": xrayPort, "protocol": "vless",
			"settings": obj{"clients": []obj{{"id": testUUID}}, "decryption": "none"},
			"streamSettings": obj{
				"network": "xhttp", "security": "tls",
				"tlsSettings":   obj{"alpn": []string{"h2"}, "certificates": []obj{{"certificateFile": certFile, "keyFile": keyFile}}},
				"xhttpSettings": obj{"path": "/xh"},
			},
		}},
		"outbounds": []obj{{"protocol": "freedom", "settings": obj{
			"redirect":   fmt.Sprintf("127.0.0.1:%d", httpsPort),
			"finalRules": []obj{{"action": "allow", "ip": []string{"127.0.0.1"}}},
		}}},
	}
	xrayFile := filepath.Join(dir, "xray-server.json")
	_ = os.WriteFile(xrayFile, []byte(configText(t, serverConfig)), 0600)
	xray := exec.Command(xrayExe(t), "run", "-c", xrayFile)
	xray.Dir = dir
	if err := xray.Start(); err != nil {
		t.Fatal("official Xray server could not start")
	}
	t.Cleanup(func() { _ = xray.Process.Kill(); _ = xray.Wait() })
	if err := waitListening(xrayPort, 10*time.Second); err != nil {
		t.Fatal("official Xray server did not listen")
	}

	ctx := proxyContext(context.Background())
	registry := service.FromContext[adapter.InboundRegistry](ctx).(*inbound.Registry)
	hysteria2.RegisterInbound(registry)
	quicPort, err := freeTestServerPort()
	if err != nil {
		t.Fatal(err)
	}
	boxConfig := obj{
		"log": obj{"disabled": true},
		"inbounds": []obj{{
			"type": "hysteria2", "listen": "0.0.0.0", "listen_port": quicPort,
			"users": []obj{{"name": "verification", "password": "test-password"}},
			"obfs":  obj{"type": "salamander", "password": "test-obfs"},
			"tls":   obj{"enabled": true, "certificate": []string{cert}, "key": []string{keyPEM}},
		}},
		"outbounds": []obj{{"type": "direct", "tag": "direct"}},
		"route": obj{"final": "direct", "rules": []obj{{
			"action": "route-options", "override_address": "127.0.0.1", "override_port": httpsPort,
		}}},
	}
	var boxOptions option.Options
	if err := boxjson.UnmarshalContext(ctx, []byte(configText(t, boxConfig)), &boxOptions); err != nil {
		t.Fatal(err)
	}
	quic, err := box.New(box.Options{Context: ctx, Options: boxOptions})
	if err != nil {
		t.Fatal(err)
	}
	if err := quic.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = quic.Close() })

	write := func(name, link, strategy string) {
		data, _ := json.Marshal(obj{
			"link": link, "strategy": strategy, "certificate": cert,
			"directHost": lan, "directPort": httpsPort,
			"urls": obj{
				"proxy":   "https://192.0.2.20/proxy",
				"blocked": "https://198.51.100.20/blocked",
				"direct":  fmt.Sprintf("https://%s:%d/direct", lan, httpsPort),
			},
		})
		if err := os.WriteFile(filepath.Join(dir, name+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	xhttpLink := fmt.Sprintf("vless://%s@127.0.0.1:%d?type=xhttp&security=tls&sni=proxy.example.com&alpn=h2&mode=packet-up&path=%%2Fxh&pcs=%s#Verification", testUUID, xrayPort, hex.EncodeToString(pin[:]))
	write("xhttp", xhttpLink, "warp-t-split")
	write("failed", strings.Replace(xhttpLink, hex.EncodeToString(pin[:]), strings.Repeat("0", 64), 1), "warp-t-split")
	write("hysteria2", fmt.Sprintf("hy2://test-password@%s:%d?sni=proxy.example.com&insecure=1&obfs=salamander&obfs-password=test-obfs#Verification", lan, quicPort), "warp-q-google6")
	metadata, _ := json.Marshal(obj{"reversePort": xrayPort, "httpsPort": httpsPort})
	_ = os.WriteFile(filepath.Join(dir, "ready.json"), metadata, 0600)
	t.Log("throwaway XHTTP, Hysteria2 and HTTPS servers are ready")
	for {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Logf("HTTPS requests answered: %d; requests to direct test path: %d", requests.Load(), directRequests.Load())
}
