//go:build linux

package collectors

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"netdiag/internal/schema"
)

// ------------------------------------------------------- proxy / PAC (L7, §4.1)

// proxyCollector reads the proxy environment (the Linux reality of "system
// proxy"), TCP-checks a configured proxy's reachability, and looks for a
// WPAD name — proxy-configured-but-unreachable is a classic silent breaker.
type proxyCollector struct{}

func (proxyCollector) Name() string      { return "proxy" }
func (proxyCollector) Privilege() string { return schema.PrivUnprivileged }

func (proxyCollector) Collect(ctx context.Context) (map[string]any, error) {
	proxyURL := firstEnv("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY")
	data := map[string]any{
		"proxy_configured": proxyURL != "",
	}
	if proxyURL != "" {
		data["proxy_url"] = proxyURL
		if host := proxyHostPort(proxyURL); host != "" {
			d := net.Dialer{Timeout: 2 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", host)
			if err == nil {
				conn.Close()
			}
			data["proxy_reachable"] = err == nil
		}
	}
	// WPAD: if the name resolves, auto-proxy discovery is in play on this
	// net — so fetch and validate the PAC it points to (§4.1: "PAC file
	// reachability and validity").
	wctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(wctx, "wpad")
	wpad := err == nil && len(addrs) > 0
	data["wpad_resolvable"] = wpad
	pacURL := firstEnv("auto_proxy", "AUTO_PROXY")
	if pacURL == "" && wpad {
		pacURL = "http://wpad/wpad.dat"
	}
	if pacURL != "" {
		data["pac_url_configured"] = true
		fetched, valid := fetchPAC(ctx, pacURL)
		data["pac_fetched"] = fetched
		data["pac_valid"] = valid
	}

	// TLS-inspection middlebox heuristic: a proxy-vendor CA in the system
	// trust store is why "odd sites break TLS only here".
	if vendor := tlsInspectionCA(); vendor != "" {
		data["tls_inspection_ca_suspected"] = true
		data["tls_inspection_ca_vendor"] = vendor
	} else {
		data["tls_inspection_ca_suspected"] = false
	}
	return data, nil
}

// tlsInspectionCA scans the system CA bundle for the middlebox vendors
// whose roots mean TLS is being re-signed on the way through.
func tlsInspectionCA() string {
	vendors := []string{"Zscaler", "Fortinet", "FortiGate", "Blue Coat", "Bluecoat",
		"Netskope", "Forcepoint", "WatchGuard", "Sophos", "Cisco Umbrella", "Menlo Security"}
	for _, path := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		s := string(b)
		for _, v := range vendors {
			if strings.Contains(s, v) {
				return v
			}
		}
	}
	return ""
}
