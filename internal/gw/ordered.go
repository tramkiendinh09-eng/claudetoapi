package gw

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"claudetoapi/internal/tlsfp"
)

// orderedTransport writes HTTP/1.1 requests by hand instead of going through
// net/http's writer. Go's Header.WriteSubset emits headers in ALPHABETICAL
// order; the real CLI emits them in Node's fixed order. Header order is part
// of the client fingerprint, so we serialize the request ourselves over the
// fingerprinted TLS connection and keep connections alive in a small pool.

// headerWireOrder is the real claude-cli header order (lower-case keys).
// Keys not listed here are appended alphabetically after (mimic mode emits
// none; passthrough clients may).
var headerWireOrder = []string{
	"host",
	"accept",
	"x-stainless-retry-count",
	"x-stainless-timeout",
	"x-stainless-lang",
	"x-stainless-package-version",
	"x-stainless-os",
	"x-stainless-arch",
	"x-stainless-runtime",
	"x-stainless-runtime-version",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"authorization",
	"x-app",
	"user-agent",
	"x-claude-code-session-id",
	"content-type",
	"anthropic-beta",
	"x-client-request-id",
	"accept-language",
	"sec-fetch-mode",
	"anthropic-dispatch-id",
	"anthropic-usage-limit",
	"content-length",
}

var wireOrderIndex = func() map[string]int {
	m := make(map[string]int, len(headerWireOrder))
	for i, k := range headerWireOrder {
		m[k] = i
	}
	return m
}()

type pooledConn struct {
	conn    net.Conn
	buf     *bufio.Reader
	expires time.Time
}

// OrderedTransport is an http.RoundTripper with wire-exact header order and
// a simple keep-alive pool keyed by (proxy, host).
type OrderedTransport struct {
	proxyURL string

	mu    sync.Mutex
	idle  map[string][]*pooledConn
	stats struct {
		dials   uint64
		reuses  uint64
		dropped uint64
	}
}

var (
	transportPoolMu sync.Mutex
	transportPool   = map[string]*OrderedTransport{}
)

// SharedOrderedTransport returns one transport per proxy target.
func SharedOrderedTransport(proxyURL string) *OrderedTransport {
	transportPoolMu.Lock()
	defer transportPoolMu.Unlock()
	if t, ok := transportPool[proxyURL]; ok {
		return t
	}
	t := &OrderedTransport{proxyURL: proxyURL, idle: map[string][]*pooledConn{}}
	transportPool[proxyURL] = t
	return t
}

const idleConnTTL = 75 * time.Second

func (t *OrderedTransport) get(key string) *pooledConn {
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		n := len(t.idle[key])
		if n == 0 {
			return nil
		}
		pc := t.idle[key][n-1]
		t.idle[key] = t.idle[key][:n-1]
		if time.Now().After(pc.expires) {
			_ = pc.conn.Close()
			t.stats.dropped++
			continue
		}
		t.stats.reuses++
		return pc
	}
}

func (t *OrderedTransport) put(key string, pc *pooledConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.idle[key]) >= 4 {
		_ = pc.conn.Close()
		t.stats.dropped++
		return
	}
	pc.expires = time.Now().Add(idleConnTTL)
	t.idle[key] = append(t.idle[key], pc)
}

// Stats reports pool counters (admin observability).
func (t *OrderedTransport) Stats() (dials, reuses, dropped uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stats.dials, t.stats.reuses, t.stats.dropped
}

func (t *OrderedTransport) dial(ctx context.Context, scheme, addr string) (*pooledConn, error) {
	var (
		conn net.Conn
		err  error
	)
	if scheme == "http" {
		// Plain HTTP upstream (test rigs, self-hosted relays): no TLS layer.
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = tlsfp.Dial(ctx, "tcp", addr, t.proxyURL)
	}
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.stats.dials++
	t.mu.Unlock()
	return &pooledConn{conn: conn, buf: bufio.NewReaderSize(conn, 32*1024)}, nil
}

// RoundTrip implements http.RoundTripper with byte-controlled output.
func (t *OrderedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
		return nil, fmt.Errorf("ordered transport only supports http/https")
	}
	var body []byte
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		body = raw
	}
	addr := req.URL.Host
	if !strings.Contains(addr, ":") {
		if req.URL.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}
	key := addr

	pc := t.get(key)
	reused := pc != nil
	if pc == nil {
		var err error
		pc, err = t.dial(req.Context(), req.URL.Scheme, addr)
		if err != nil {
			return nil, err
		}
	}

	resp, err := t.exchange(pc, req, body)
	if err != nil {
		_ = pc.conn.Close()
		if reused {
			// Stale pooled connection: retry once on a fresh one.
			pc, err = t.dial(req.Context(), req.URL.Scheme, addr)
			if err != nil {
				return nil, err
			}
			resp, err = t.exchange(pc, req, body)
			if err != nil {
				_ = pc.conn.Close()
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	keepAlive := !resp.Close && resp.ProtoAtLeast(1, 1)
	resp.Body = &poolBody{ReadCloser: resp.Body, transport: t, key: key, pc: pc, keep: keepAlive}
	return resp, nil
}

// exchange writes the request and reads the response header.
func (t *OrderedTransport) exchange(pc *pooledConn, req *http.Request, body []byte) (*http.Response, error) {
	_ = pc.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := writeOrderedRequest(pc.conn, req, body); err != nil {
		return nil, err
	}
	_ = pc.conn.SetWriteDeadline(time.Time{})
	// Header read deadline only; the streaming body has none.
	_ = pc.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	resp, err := http.ReadResponse(pc.buf, req)
	_ = pc.conn.SetReadDeadline(time.Time{})
	return resp, err
}

// writeOrderedRequest serializes the request with Node's header order.
func writeOrderedRequest(w io.Writer, req *http.Request, body []byte) error {
	var b bytes.Buffer
	uri := req.URL.RequestURI()
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, uri)

	wireKeys := make(map[string]string, len(req.Header)) // lower -> actual key
	for k := range req.Header {
		wireKeys[strings.ToLower(k)] = k
	}
	// Host: first (Node puts it immediately after the request line).
	if hostKey, ok := wireKeys["host"]; ok {
		fmt.Fprintf(&b, "%s: %s\r\n", hostKey, req.Header.Get(hostKey))
	} else {
		fmt.Fprintf(&b, "Host: %s\r\n", req.URL.Host)
	}
	written := map[string]bool{"host": true}

	emit := func(lower string) {
		if written[lower] {
			return
		}
		k, ok := wireKeys[lower]
		if !ok {
			return
		}
		written[lower] = true
		for _, v := range req.Header[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	for _, k := range headerWireOrder {
		emit(k)
	}
	// Unlisted headers: stable alphabetical tail.
	var rest []string
	for lower := range wireKeys {
		if !written[lower] {
			rest = append(rest, lower)
		}
	}
	sort.Strings(rest)
	for _, lower := range rest {
		emit(lower)
	}
	fmt.Fprintf(&b, "content-length: %d\r\n", len(body))
	b.WriteString("\r\n")
	if _, err := w.Write(b.Bytes()); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// poolBody returns a cleanly-drained keep-alive connection to the pool.
type poolBody struct {
	io.ReadCloser
	transport *OrderedTransport
	key       string
	pc        *pooledConn
	keep      bool
	drained   bool
	returned  bool
}

func (p *poolBody) Read(b []byte) (int, error) {
	n, err := p.ReadCloser.Read(b)
	if err == io.EOF {
		p.drained = true
	}
	return n, err
}

func (p *poolBody) Close() error {
	err := p.ReadCloser.Close()
	if p.returned {
		return err
	}
	p.returned = true
	if p.keep && p.drained && err == nil {
		p.transport.put(p.key, p.pc)
	} else {
		_ = p.pc.conn.Close()
		p.transport.mu.Lock()
		p.transport.stats.dropped++
		p.transport.mu.Unlock()
	}
	return err
}
