// Package tlsfp gives outbound HTTPS a Node.js 24.x TLS fingerprint using
// uTLS. Parameters (cipher suites, curves, signature algorithms, extension
// order incl. GREASE-ECH) reproduce the ClientHello that Claude Code's Node
// runtime presents; target JA3 44f88fca027f27bab4bb08d4af15f23e,
// JA4 t13d1714h1_5b57614c22b0_7baf387fc6ff.
package tlsfp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// nodeCipherSuites: 17 suites, order critical (TLS1.3 first, then ECDHE,
// then RSA) as captured from Node.js 24.x.
var nodeCipherSuites = []uint16{
	0x1301, 0x1302, 0x1303,
	0xc02b, 0xc02f, 0xc02c, 0xc030,
	0xcca9, 0xcca8,
	0xc009, 0xc013, 0xc00a, 0xc014,
	0x009c, 0x009d,
	0x002f, 0x0035,
}

var nodeCurves = []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}

var nodeSigAlgs = []utls.SignatureScheme{
	0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
}

// nodeExtensionOrder is the Node.js 24.x ClientHello extension order,
// including ECH (0xfe0d) which is sent as GREASE-ECH.
var nodeExtensionOrder = []uint16{
	0,     // server_name
	0xfe0d, // encrypted_client_hello (GREASE payload)
	23,    // extended_master_secret
	0xff01, // renegotiation_info
	10,    // supported_groups
	11,    // ec_point_formats
	35,    // session_ticket
	16,    // ALPN (http/1.1 — Node's undici default, no h2)
	5,     // status_request
	13,    // signature_algorithms
	18,    // SCT
	51,    // key_share (X25519)
	45,    // psk_key_exchange_modes (psk_dhe_ke)
	43,    // supported_versions (1.3, 1.2)
}

// nodeSpec builds the ClientHello spec.
func nodeSpec() *utls.ClientHelloSpec {
	extensions := make([]utls.TLSExtension, 0, len(nodeExtensionOrder))
	for _, id := range nodeExtensionOrder {
		switch id {
		case 0:
			extensions = append(extensions, &utls.SNIExtension{})
		case 5:
			extensions = append(extensions, &utls.StatusRequestExtension{})
		case 10:
			extensions = append(extensions, &utls.SupportedCurvesExtension{Curves: nodeCurves})
		case 11:
			extensions = append(extensions, &utls.SupportedPointsExtension{SupportedPoints: []uint8{0}})
		case 13:
			extensions = append(extensions, &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: nodeSigAlgs})
		case 16:
			extensions = append(extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
		case 18:
			extensions = append(extensions, &utls.SCTExtension{})
		case 23:
			extensions = append(extensions, &utls.ExtendedMasterSecretExtension{})
		case 35:
			extensions = append(extensions, &utls.SessionTicketExtension{})
		case 43:
			extensions = append(extensions, &utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}})
		case 45:
			extensions = append(extensions, &utls.PSKKeyExchangeModesExtension{Modes: []uint8{uint8(utls.PskModeDHE)}})
		case 51:
			extensions = append(extensions, &utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}})
		case 0xfe0d:
			// GREASE ECH with random payload — an empty generic extension
			// gets rejected by ECH-validating servers.
			extensions = append(extensions, &utls.GREASEEncryptedClientHelloExtension{})
		case 0xff01:
			extensions = append(extensions, &utls.RenegotiationInfoExtension{})
		default:
			extensions = append(extensions, &utls.GenericExtension{Id: id})
		}
	}
	return &utls.ClientHelloSpec{
		CipherSuites:       nodeCipherSuites,
		CompressionMethods: []uint8{0},
		Extensions:         extensions,
		TLSVersMax:         utls.VersionTLS13,
		TLSVersMin:         utls.VersionTLS10,
	}
}

// handshake wraps conn in a uTLS client with the Node spec.
func handshake(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	tlsConn := utls.UClient(conn, &utls.Config{ServerName: host}, utls.HelloCustom)
	if err := tlsConn.ApplyPreset(nodeSpec()); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("apply tls preset: %w", err)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return tlsConn, nil
}

// dialTLS connects to addr (directly, via HTTP CONNECT or via SOCKS5 when
// proxyURL is set) and completes the fingerprinted handshake.
func dialTLS(ctx context.Context, network, addr, proxyURL string) (net.Conn, error) {
	if proxyURL == "" {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return handshake(ctx, conn, addr)
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}
	switch stringsLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		dial, err := proxy.SOCKS5("tcp", withDefaultPort(u.Host, "1080"), auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("socks5 dialer: %w", err)
		}
		conn, err := dial.Dial(network, addr)
		if err != nil {
			return nil, fmt.Errorf("socks5 connect: %w", err)
		}
		return handshake(ctx, conn, addr)
	default: // http, https proxies via CONNECT
		var d net.Dialer
		port := "80"
		if stringsLower(u.Scheme) == "https" {
			port = "443"
		}
		conn, err := d.DialContext(ctx, network, withDefaultPort(u.Host, port))
		if err != nil {
			return nil, fmt.Errorf("connect proxy: %w", err)
		}
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if u.User != nil {
			pw, _ := u.User.Password()
			req.Header.Set("Proxy-Authorization", basicAuth(u.User.Username(), pw))
		}
		if err := req.Write(conn); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("write CONNECT: %w", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read CONNECT response: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy CONNECT status %s", resp.Status)
		}
		return handshake(ctx, conn, addr)
	}
}

// Dial is the exported fingerprinted dialer used by the ordered transport.
func Dial(ctx context.Context, network, addr, proxyURL string) (net.Conn, error) {
	return dialTLS(ctx, network, addr, proxyURL)
}

func withDefaultPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
}

func stringsLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			out[i] = s[i] + 32
		} else {
			out[i] = s[i]
		}
	}
	return string(out)
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// transportCache shares one http.Transport per proxy target.
var (
	transportMu sync.Mutex
	transports  = map[string]*http.Transport{}
)

// Transport returns a pooled *http.Transport whose TLS dials carry the
// Node.js fingerprint. proxyURL == "" means direct.
func Transport(proxyURL string) *http.Transport {
	transportMu.Lock()
	defer transportMu.Unlock()
	if t, ok := transports[proxyURL]; ok {
		return t
	}
	t := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLS(ctx, network, addr, proxyURL)
		},
		ForceAttemptHTTP2:     false, // Node/undici speaks http/1.1 here
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    false,
	}
	transports[proxyURL] = t
	return t
}

// PlainTransport is a stdlib-TLS transport for non-fingerprinted traffic
// (OAuth endpoints, usage polling).
func PlainTransport(proxyURL string) *http.Transport {
	t := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			t.Proxy = http.ProxyURL(u)
			t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
	}
	return t
}
