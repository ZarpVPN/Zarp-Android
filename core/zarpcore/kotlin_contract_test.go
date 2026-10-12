package zarpcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These fixtures are produced and asserted by Kotlin's OutboundContractTest.
// Construction uses the real sing-box JSON decoder and the linked Xray engine.
func TestKotlinOutboundContracts(t *testing.T) {
	files, err := filepath.Glob("testdata/kotlin/*.json")
	if err != nil || len(files) != 24 {
		t.Fatal("the 24 checked-in Kotlin outbound contracts are required")
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Host    string
				Address string
				Port    int
				QUIC    bool
				Config  json.RawMessage
				Xray    json.RawMessage
			}
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			options := NewServerOptions()
			options.SetServer(fixture.Host, fixture.Address, fixture.Port)
			options.SetQUIC(fixture.QUIC)
			if len(fixture.Xray) != 0 {
				options.SetXrayOutbound(string(fixture.Xray))
			}
			proxy, err := NewServerProxy(string(fixture.Config), options, nil)
			if err != nil {
				t.Fatalf("native engines rejected Kotlin outbound contract: %v", err)
			}
			if proxy.SocksPort() < 1 {
				t.Fatal("SOCKS inbound did not bind")
			}
			proxy.Close()
		})
	}
}
