package zarpcore

// V2Ray/Xray GeoIPList and GeoSiteList wire format:
// https://github.com/v2fly/v2ray-core/blob/master/app/router/routercommon/common.proto
// Only selected categories are expanded; the proxy uses normal sing-box rules,
// not the legacy geoip/geosite options removed from sing-box 1.12.
import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

const maxGeoBytes = 64 << 20

type geoField struct {
	num   protowire.Number
	typ   protowire.Type
	data  []byte
	value uint64
}

func walkGeo(data []byte, visit func(geoField) error) error {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 || num <= 0 {
			return errors.New("invalid protobuf field")
		}
		data = data[n:]
		f := geoField{num: num, typ: typ}
		switch typ {
		case protowire.BytesType:
			f.data, n = protowire.ConsumeBytes(data)
		case protowire.VarintType:
			f.value, n = protowire.ConsumeVarint(data)
		case protowire.Fixed32Type, protowire.Fixed64Type:
			n = protowire.ConsumeFieldValue(num, typ, data)
		default:
			return errors.New("unsupported protobuf wire type")
		}
		if n < 0 {
			return errors.New("truncated protobuf field")
		}
		if err := visit(f); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

type geoEntry struct {
	records [][]byte
	inverse bool
}
type geoDatabase map[string]geoEntry

var geoTagPattern = regexp.MustCompile(`^[a-zA-Z0-9_!.-]{1,128}$`)

func readGeo(path, kind string) (geoDatabase, error) {
	if kind != "geoip" && kind != "geosite" {
		return nil, errors.New("unknown database type")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: database is not downloaded", kind)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxGeoBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxGeoBytes {
		return nil, errors.New("invalid database size")
	}
	db := make(geoDatabase)
	recordCount := 0
	err = walkGeo(data, func(field geoField) error {
		if field.num != 1 {
			return nil
		}
		if field.typ != protowire.BytesType {
			return errors.New("invalid database entry")
		}
		var name string
		var entry geoEntry
		err := walkGeo(field.data, func(f geoField) error {
			switch f.num {
			case 1:
				if f.typ != protowire.BytesType {
					return errors.New("invalid category")
				}
				name = strings.ToLower(string(f.data))
			case 2:
				if f.typ != protowire.BytesType || recordCount >= 2000000 {
					return errors.New("invalid record")
				}
				recordCount++
				entry.records = append(entry.records, f.data)
			case 3:
				if kind == "geoip" {
					if f.typ != protowire.VarintType {
						return errors.New("invalid inverse flag")
					}
					entry.inverse = f.value != 0
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !geoTagPattern.MatchString(name) || len(entry.records) == 0 || len(db) >= 20000 {
			return errors.New("invalid or empty category")
		}
		if _, exists := db[name]; exists {
			return errors.New("duplicate category")
		}
		db[name] = entry
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(db) == 0 {
		return nil, errors.New("no categories found")
	}
	return db, nil
}

func geoCIDR(data []byte) (string, error) {
	var ip []byte
	var prefix uint64
	err := walkGeo(data, func(f geoField) error {
		if f.num == 1 {
			if f.typ != protowire.BytesType {
				return errors.New("invalid IP")
			}
			ip = f.data
		}
		if f.num == 2 {
			if f.typ != protowire.VarintType {
				return errors.New("invalid prefix")
			}
			prefix = f.value
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || prefix > uint64(addr.BitLen()) {
		return "", errors.New("invalid CIDR")
	}
	return netip.PrefixFrom(addr, int(prefix)).Masked().String(), nil
}

type geoDomain struct {
	typ   uint64
	value string
	attrs map[string]bool
}

func parseGeoDomain(data []byte) (geoDomain, error) {
	d := geoDomain{attrs: make(map[string]bool)}
	err := walkGeo(data, func(f geoField) error {
		switch f.num {
		case 1:
			if f.typ != protowire.VarintType {
				return errors.New("invalid domain type")
			}
			d.typ = f.value
		case 2:
			if f.typ != protowire.BytesType {
				return errors.New("invalid domain")
			}
			d.value = string(f.data)
		case 3:
			if f.typ != protowire.BytesType {
				return errors.New("invalid attribute")
			}
			var key string
			present := true
			if err := walkGeo(f.data, func(a geoField) error {
				if a.num == 1 {
					if a.typ != protowire.BytesType {
						return errors.New("invalid attribute key")
					}
					key = strings.ToLower(string(a.data))
				}
				if a.num == 2 {
					if a.typ != protowire.VarintType {
						return errors.New("invalid attribute value")
					}
					present = a.value != 0
				}
				return nil
			}); err != nil {
				return err
			}
			if !geoTagPattern.MatchString(key) {
				return errors.New("invalid attribute name")
			}
			d.attrs[key] = present
		}
		return nil
	})
	if err != nil {
		return d, err
	}
	if d.typ > 3 || d.value == "" || len(d.value) > 4096 || !utf8.ValidString(d.value) || strings.ContainsAny(d.value, "\x00\r\n") {
		return d, errors.New("invalid domain record")
	}
	if d.typ == 1 {
		if _, err := regexp.Compile(d.value); err != nil {
			return d, errors.New("invalid domain regex")
		}
	}
	return d, nil
}

// GeoDataInfo validates the entire file before the downloader replaces a usable database.
func GeoDataInfo(kind, path string) (string, error) {
	db, err := readGeo(path, kind)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(db))
	for name, entry := range db {
		for _, record := range entry.records {
			if kind == "geoip" {
				_, err = geoCIDR(record)
			} else {
				_, err = parseGeoDomain(record)
			}
			if err != nil {
				return "", err
			}
		}
		names = append(names, name)
	}
	sort.Strings(names)
	data, err := json.Marshal(names)
	return string(data), err
}

type routeToken struct{ kind, value, attr string }

func parseRouteToken(raw string) (routeToken, error) {
	s := strings.TrimSpace(raw)
	if len(s) == 0 || len(s) > 4096 {
		return routeToken{}, errors.New("invalid rule length")
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return routeToken{"ip_cidr", p.Masked().String(), ""}, nil
	}
	if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" {
		return routeToken{"ip_cidr", netip.PrefixFrom(ip, ip.BitLen()).String(), ""}, nil
	}
	kind, value, hasType := strings.Cut(s, ":")
	if !hasType {
		if strings.Trim(s, "0123456789.") == "" {
			return routeToken{}, errors.New("invalid IP address")
		}
		kind, value = "domain", s
	}
	kind = strings.ToLower(kind)
	switch kind {
	case "geoip", "geosite":
		name, attr, _ := strings.Cut(strings.ToLower(value), "@")
		if !geoTagPattern.MatchString(name) || (attr != "" && (kind != "geosite" || !geoTagPattern.MatchString(strings.TrimPrefix(attr, "!")))) || strings.HasSuffix(value, "@") {
			return routeToken{}, errors.New("invalid geo category")
		}
		return routeToken{kind, name, attr}, nil
	case "regexp":
		if value == "" {
			return routeToken{}, errors.New("empty regex")
		}
		if _, err := regexp.Compile(value); err != nil {
			return routeToken{}, errors.New("invalid regex (RE2)")
		}
		return routeToken{"domain_regex", value, ""}, nil
	case "keyword":
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return routeToken{}, errors.New("invalid keyword")
		}
		return routeToken{"domain_keyword", value, ""}, nil
	case "domain", "full":
		value = strings.TrimSuffix(strings.ToLower(value), ".")
		if len(value) == 0 || len(value) > 253 {
			return routeToken{}, errors.New("invalid domain")
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return routeToken{}, errors.New("invalid domain")
			}
			for _, c := range label {
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
					return routeToken{}, errors.New("use an ASCII or punycode domain")
				}
			}
		}
		if kind == "full" {
			return routeToken{"domain", value, ""}, nil
		}
		return routeToken{"domain_suffix", value, ""}, nil
	}
	return routeToken{}, errors.New("unknown rule type or invalid IP/CIDR")
}

func routeTokens(rulesJSON string) (map[string][]routeToken, error) {
	if len(rulesJSON) > 1<<20 {
		return nil, errors.New("too many rules")
	}
	var raw map[string][]string
	if err := json.Unmarshal([]byte(rulesJSON), &raw); err != nil {
		return nil, errors.New("invalid rules")
	}
	result := make(map[string][]routeToken)
	for action, lines := range raw {
		if action != "direct" && action != "proxy" && action != "block" {
			return nil, errors.New("invalid rule action")
		}
		if len(lines) > 10000 {
			return nil, errors.New("too many rules")
		}
		for i, line := range lines {
			token, err := parseRouteToken(line)
			if err != nil {
				return nil, fmt.Errorf("%s, line %d: %w", action, i+1, err)
			}
			result[action] = append(result[action], token)
		}
	}
	return result, nil
}

// ValidateRouteRules checks syntax without requiring downloaded databases.
func ValidateRouteRules(rulesJSON string) error { _, err := routeTokens(rulesJSON); return err }

// CompileRouteRules expands just the referenced .dat categories into sing-box matchers.
// Built-in IP ranges are used only until a custom GeoIP database is downloaded.
// A missing category never becomes an empty/unconditional match or an ignored rule.
func CompileRouteRules(rulesJSON, geoipPath, geositePath, fallbackJSON string) (string, error) {
	tokens, err := routeTokens(rulesJSON)
	if err != nil {
		return "", err
	}
	var fallback map[string][]string
	if fallbackJSON != "" {
		if err := json.Unmarshal([]byte(fallbackJSON), &fallback); err != nil {
			return "", errors.New("invalid bundled GeoIP")
		}
	}
	loaded := make(map[string]geoDatabase)
	load := func(kind string) (geoDatabase, error) {
		if db, ok := loaded[kind]; ok {
			return db, nil
		}
		path := geoipPath
		if kind == "geosite" {
			path = geositePath
		}
		db, err := readGeo(path, kind)
		if err == nil {
			loaded[kind] = db
		}
		return db, err
	}
	type rule map[string]any
	compiled := make([]rule, 0, 3)
	for _, action := range []string{"block", "proxy", "direct"} {
		values := make(map[string][]string)
		matchers := []rule{}
		for _, token := range tokens[action] {
			switch token.kind {
			case "geoip":
				if token.value == "private" {
					values["ip_cidr"] = append(values["ip_cidr"], "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")
					continue
				}
				if geoipPath == "" && len(fallback[token.value]) > 0 {
					values["ip_cidr"] = append(values["ip_cidr"], fallback[token.value]...)
					continue
				}
				db, err := load("geoip")
				if err != nil {
					return "", err
				}
				entry, ok := db[token.value]
				if !ok {
					return "", fmt.Errorf("geoip:%s: category not found", token.value)
				}
				cidrs := make([]string, 0, len(entry.records))
				for _, record := range entry.records {
					value, err := geoCIDR(record)
					if err != nil {
						return "", err
					}
					cidrs = append(cidrs, value)
				}
				if entry.inverse {
					matchers = append(matchers, rule{"ip_cidr": cidrs, "invert": true})
				} else {
					values["ip_cidr"] = append(values["ip_cidr"], cidrs...)
				}
			case "geosite":
				db, err := load("geosite")
				if err != nil {
					return "", err
				}
				entry, ok := db[token.value]
				if !ok {
					return "", fmt.Errorf("geosite:%s: category not found", token.value)
				}
				matched := 0
				for _, record := range entry.records {
					d, err := parseGeoDomain(record)
					if err != nil {
						return "", err
					}
					if token.attr != "" {
						negate := strings.HasPrefix(token.attr, "!")
						present := d.attrs[strings.TrimPrefix(token.attr, "!")]
						if present == negate {
							continue
						}
					}
					key := []string{"domain_keyword", "domain_regex", "domain_suffix", "domain"}[d.typ]
					values[key] = append(values[key], d.value)
					matched++
				}
				if matched == 0 {
					return "", fmt.Errorf("geosite:%s@%s: no matching domains", token.value, token.attr)
				}
			default:
				values[token.kind] = append(values[token.kind], token.value)
			}
		}
		// Each field is a separate OR branch, so IP/domain conditions never accidentally become AND.
		for _, field := range []string{"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"} {
			if list := values[field]; len(list) > 0 {
				sort.Strings(list)
				unique := list[:0]
				for _, value := range list {
					if len(unique) == 0 || unique[len(unique)-1] != value {
						unique = append(unique, value)
					}
				}
				matchers = append(matchers, rule{field: unique})
			}
		}
		if len(matchers) == 0 {
			continue
		}
		r := rule{"type": "logical", "mode": "or", "rules": matchers}
		if action == "block" {
			r["action"] = "reject"
		} else {
			r["action"] = "route"
			r["outbound"] = action
		}
		compiled = append(compiled, r)
	}
	data, err := json.Marshal(compiled)
	return string(data), err
}
