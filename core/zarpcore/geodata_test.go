package zarpcore

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"google.golang.org/protobuf/encoding/protowire"
)

func geoBytes(number protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, number, protowire.BytesType), value)
}
func geoInt(number protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), value)
}
func geoFixture(t *testing.T, name string, records ...[]byte) string {
	t.Helper()
	entry := geoBytes(1, []byte(name))
	for _, record := range records {
		entry = append(entry, geoBytes(2, record)...)
	}
	path := filepath.Join(t.TempDir(), "test.dat")
	if err := os.WriteFile(path, geoBytes(1, entry), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGeoDataFormatsAndRouting(t *testing.T) {
	cidr := append(geoBytes(1, []byte{127, 0, 0, 0}), geoInt(2, 8)...)
	ip := geoFixture(t, "TEST", cidr)
	domain := append(geoInt(1, 2), geoBytes(2, []byte("example.org"))...)
	attribute := append(geoBytes(1, []byte("ads")), geoInt(2, 1)...)
	domain = append(domain, geoBytes(3, attribute)...)
	site := geoFixture(t, "TEST", domain)
	for kind, path := range map[string]string{"geoip": ip, "geosite": site} {
		info, err := GeoDataInfo(kind, path)
		if err != nil || info != `["test"]` {
			t.Fatalf("%s: %s %v", kind, info, err)
		}
	}
	compiled, err := CompileRouteRules(`{"direct":["geoip:test"],"block":["geosite:test@ads"],"proxy":["full:allow.example.org"]}`, ip, site, "")
	if err != nil {
		t.Fatal(err)
	}
	var rules []obj
	if err := json.Unmarshal([]byte(compiled), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || rules[0]["action"] != "reject" || rules[1]["outbound"] != "proxy" || rules[2]["outbound"] != "direct" {
		t.Fatalf("incorrect precedence: %s", compiled)
	}
	if !strings.Contains(compiled, "127.0.0.0/8") || !strings.Contains(compiled, "domain_suffix") {
		t.Fatal(compiled)
	}
	broken := obj{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1, "connect_timeout": "1s"}
	p, err := NewProxy(configText(t, localProxyConfig(broken, rules)))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	checkTCP(t, p.SocksPort(), tcpEcho(t))
	checkUDP(t, p.SocksPort())
	for _, blocked := range []string{"example.org:80", "ads.example.org:80", "allow.example.org:80"} {
		dialer, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", p.SocksPort()), nil, &net.Dialer{Timeout: time.Second})
		if conn, err := dialer.Dial("tcp", blocked); err == nil {
			conn.Close()
			t.Fatalf("blocked domain connected: %s", blocked)
		}
	}
}

func TestGeoRulesRejectIncompleteOrInvalidData(t *testing.T) {
	for _, text := range []string{`{"direct":["1.2.3.4/999"]}`, `{"block":["regexp:["]}`, `{"direct":["geosite:cn@"]}`, `{"proxy":["https://example.com"]}`, `{"block":["999.1.2.3"]}`} {
		if ValidateRouteRules(text) == nil {
			t.Fatalf("accepted invalid rules: %s", text)
		}
	}
	if err := ValidateRouteRules(`{"direct":["GeoIP:CN","Domain:Example.com"],"block":["Geosite:category-ads-all"]}`); err != nil {
		t.Fatal("rule type prefixes should be case insensitive:", err)
	}
	for _, text := range []string{`{"direct":["geosite:missing"]}`, `{"block":["geoip:missing"]}`} {
		if _, err := CompileRouteRules(text, "", "", "{}"); err == nil {
			t.Fatal("missing data silently ignored")
		}
	}
	path := filepath.Join(t.TempDir(), "corrupt.dat")
	for _, data := range [][]byte{nil, []byte("<html>error</html>"), {0x0a, 0xff}, geoBytes(1, geoBytes(1, []byte("empty")))} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := GeoDataInfo("geoip", path); err == nil {
			t.Fatalf("accepted corrupt database: %x", data)
		}
	}
	wrongIP := geoFixture(t, "test", append(geoBytes(1, []byte{1, 2, 3}), geoInt(2, 32)...))
	if _, err := GeoDataInfo("geoip", wrongIP); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	compiled, err := CompileRouteRules(`{"direct":["geoip:ru"]}`, "", "", `{"ru":["5.8.0.0/16"]}`)
	if err != nil || !strings.Contains(compiled, "5.8.0.0/16") {
		t.Fatalf("bundled fallback: %s %v", compiled, err)
	}
	other := geoFixture(t, "test", append(geoBytes(1, []byte{1, 2, 3, 0}), geoInt(2, 24)...))
	if _, err := CompileRouteRules(`{"direct":["geoip:ru"]}`, other, "", `{"ru":["5.8.0.0/16"]}`); err == nil {
		t.Fatal("custom database silently fell back to bundled data")
	}
}

func TestBlockAndProxyOverrideLAN(t *testing.T) {
	target := tcpEcho(t)
	broken := obj{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1, "connect_timeout": "1s"}
	for _, action := range []string{"block", "proxy"} {
		text := fmt.Sprintf(`{"direct":["geoip:private"],%q:["127.0.0.1"]}`, action)
		compiled, err := CompileRouteRules(text, "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		var rules []obj
		if err := json.Unmarshal([]byte(compiled), &rules); err != nil {
			t.Fatal(err)
		}
		p, err := NewProxy(configText(t, localProxyConfig(broken, rules)))
		if err != nil {
			t.Fatal(err)
		}
		dialer, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", p.SocksPort()), nil, &net.Dialer{Timeout: time.Second})
		if conn, err := dialer.Dial("tcp", target); err == nil {
			conn.Close()
			t.Fatalf("%s rule leaked to LAN direct", action)
		}
		p.Close()
	}
}

func TestGeoDataInverseAndIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::").To16()
	record := append(geoBytes(1, ip), geoInt(2, 32)...)
	entry := append(geoBytes(1, []byte("test")), geoBytes(2, record)...)
	entry = append(entry, geoInt(3, 1)...)
	path := filepath.Join(t.TempDir(), "inverse.dat")
	if err := os.WriteFile(path, geoBytes(1, entry), 0600); err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileRouteRules(`{"block":["geoip:test"]}`, path, "", "")
	if err != nil || !strings.Contains(compiled, `"invert":true`) || !strings.Contains(compiled, "2001:db8::/32") {
		t.Fatalf("%s %v", compiled, err)
	}
}
