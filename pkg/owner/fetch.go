// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package owner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/carabiner-dev/vcslocator"
)

// MaxDocumentSize caps the owner document size.
const MaxDocumentSize = 1 << 20

// DefaultTimeout bounds a single owner document fetch.
const DefaultTimeout = 20 * time.Second

// Fetcher downloads owner documents. Its zero value is safe and strict: only
// https to public hosts, no redirects, bounded size and time.
type Fetcher struct {
	// Timeout for one fetch. DefaultTimeout when zero.
	Timeout time.Duration

	// MaxSize of a document. MaxDocumentSize when zero.
	MaxSize int64

	// AllowPrivate disables the public-address check on resolved IPs and
	// accepts http:// and file:// owner URLs. Only for tests and local
	// experimentation, never in CI.
	AllowPrivate bool

	// UserAgent sent with http requests.
	UserAgent string

	// Transport overrides the http transport (tests). The dialer guard is
	// not applied to a custom transport.
	Transport http.RoundTripper
}

// Fetch downloads the document at the owner URL.
func (f *Fetcher) Fetch(ctx context.Context, o *Owner) ([]byte, error) {
	if o == nil {
		return nil, errors.New("nil owner")
	}
	switch o.Kind {
	case KindHTTPS:
		return f.fetchHTTP(ctx, o.URL)
	case KindGit:
		return f.fetchGit(ctx, o.URL)
	default:
		return nil, fmt.Errorf("unknown owner kind %q", o.Kind)
	}
}

func (f *Fetcher) maxSize() int64 {
	if f.MaxSize > 0 {
		return f.MaxSize
	}
	return MaxDocumentSize
}

func (f *Fetcher) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	return DefaultTimeout
}

// guardedDialer resolves the host and refuses to connect to any address
// that is not public. Checking the resolved addresses at dial time (not just
// the host name beforehand) closes the DNS rebinding window.
func (f *Fetcher) guardedDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", host, err)
		}
		var lastErr error
		for _, ip := range ips {
			if !f.AllowPrivate && !IsPublicIP(ip.IP) {
				return nil, fmt.Errorf("owner host %s resolves to non-public address %s", host, ip.IP)
			}
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no addresses for %s", host)
		}
		return nil, lastErr
	}
}

func (f *Fetcher) client() *http.Client {
	transport := f.Transport
	if transport == nil {
		transport = &http.Transport{
			DialContext:           f.guardedDialer(),
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			DisableKeepAlives:     true,
			Proxy:                 nil, // never honor proxy env for owner fetches
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   f.timeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not followed when fetching owner documents")
		},
	}
}

func (f *Fetcher) fetchHTTP(ctx context.Context, u *url.URL) ([]byte, error) {
	if u.Scheme != schemeHTTPS && (!f.AllowPrivate || u.Scheme != "http") {
		return nil, fmt.Errorf("refusing to fetch owner document over %s", u.Scheme)
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/yaml, application/json, text/yaml, text/plain;q=0.5")
	ua := f.UserAgent
	if ua == "" {
		ua = "claim/0 (+https://github.com/policylabs/claim)"
	}
	req.Header.Set("User-Agent", ua)
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", u, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: unexpected status %s", u, resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		mt := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
		switch mt {
		case "text/html", "application/xhtml+xml", "application/javascript", "text/javascript", "image/svg+xml":
			return nil, fmt.Errorf("owner document at %s has content type %s, not a yaml or json document", u, mt)
		}
	}
	if resp.ContentLength > f.maxSize() {
		return nil, fmt.Errorf("owner document at %s is too large (%d bytes)", u, resp.ContentLength)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, f.maxSize()+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", u, err)
	}
	if int64(len(data)) > f.maxSize() {
		return nil, fmt.Errorf("owner document at %s is too large (max %d bytes)", u, f.maxSize())
	}
	return data, nil
}

// fetchGit reads the document from a git repository through a VCS locator.
// The URL carries the repository path, an optional @ref and the document
// path in the fragment.
func (f *Fetcher) fetchGit(ctx context.Context, u *url.URL) ([]byte, error) {
	locator := GitLocator(u)
	if strings.HasPrefix(locator, "file://") && !f.AllowPrivate {
		return nil, errors.New("refusing to read owner document from a local repository")
	}
	if !f.AllowPrivate {
		// Resolve the host now and refuse non public addresses. go-git does
		// its own dialing, so this check is best-effort (no rebinding guard).
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", u.Hostname(), err)
		}
		for _, ip := range ips {
			if !IsPublicIP(ip.IP) {
				return nil, fmt.Errorf("owner host %s resolves to non-public address %s", u.Hostname(), ip.IP)
			}
		}
	}
	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- vcslocator.CopyFile(locator, &limitedWriter{w: &buf, max: f.maxSize()})
	}()
	ctx, cancel := context.WithTimeout(ctx, f.timeout()*3) // clones take longer
	defer cancel()
	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", locator, err)
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("reading %s: %w", locator, ctx.Err())
	}
	return buf.Bytes(), nil
}

// GitLocator renders the owner URL back as a VCS locator string. The URL
// scheme carries the transport; the fragment carries the file path.
func GitLocator(u *url.URL) string {
	scheme := u.Scheme
	if scheme == schemeHTTPS {
		scheme = "git+https"
	}
	if scheme == "file" {
		return "file://" + u.Path + "#" + u.Fragment
	}
	return scheme + "://" + u.Host + u.Path + "#" + u.Fragment
}

type limitedWriter struct {
	w   io.Writer
	max int64
	n   int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	lw.n += int64(len(p))
	if lw.n > lw.max {
		return 0, fmt.Errorf("owner document exceeds %d bytes", lw.max)
	}
	return lw.w.Write(p)
}
