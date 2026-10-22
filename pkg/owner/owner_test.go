// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package owner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/policylabs/claim/pkg/config"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestValidateHostname(t *testing.T) {
	t.Parallel()
	for _, h := range []string{"example.com", "a.b.example.org", "xn--bcher-kva.example", "EXAMPLE.COM", "example.com.", "bücher.example"} {
		require.NoError(t, ValidateHostname(h), h)
	}
	for _, h := range []string{
		"", "localhost", "foo.localhost", "intranet.local", "svc.internal", "example", "-bad.com", "bad-.com",
		"127.0.0.1", "::1", "[::1]", "10.0.0.1", "exa mple.com", "example.com:443", "user@example.com",
		"example.com/path", "1.2.3", "a..b", "ex%20ample.com",
	} {
		require.Error(t, ValidateHostname(h), h)
	}
}

func TestIsPublicIP(t *testing.T) {
	t.Parallel()
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "93.184.216.34"} {
		require.True(t, IsPublicIP(net.ParseIP(ip)), ip)
	}
	for _, ip := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
		"::1", "fe80::1", "fc00::1", "::", "224.0.0.1", "::ffff:127.0.0.1", "192.0.2.1", "2001:db8::1",
	} {
		require.False(t, IsPublicIP(net.ParseIP(ip)), ip)
	}
}

func TestParseOwnerURL(t *testing.T) {
	t.Parallel()
	u, kind, err := ParseOwnerURL("https://example.com/.well-known/claim.yaml")
	require.NoError(t, err)
	require.Equal(t, KindHTTPS, kind)
	require.Equal(t, "example.com", u.Hostname())

	u, kind, err = ParseOwnerURL("git+https://github.com/org/repo@v1#owners/claim.yaml")
	require.NoError(t, err)
	require.Equal(t, KindGit, kind)
	require.Equal(t, "/org/repo@v1", u.Path)
	require.Equal(t, "owners/claim.yaml", u.Fragment)
	require.Equal(t, "git+https://github.com/org/repo@v1#owners/claim.yaml", GitLocator(u))

	for _, bad := range []string{
		"", "http://example.com/", "file:///etc/passwd", "ssh://git@github.com/org/repo", "git+ssh://github.com/org/repo",
		"https://user:pw@example.com/", "https://example.com:8443/", "https://127.0.0.1/", "https://[::1]/",
		"https://localhost/", "https://example.com/../x", "git+https://github.com/onlyorg", "https://exa mple.com/",
		"git+https://github.com/org/repo?x=1", "ftp://example.com/",
	} {
		_, _, err := ParseOwnerURL(bad)
		require.Error(t, err, bad)
	}
}

func TestExtractURL(t *testing.T) {
	t.Parallel()
	s, err := ExtractURL([]byte("  https://example.com \n# comment\n"), "text", "")
	require.NoError(t, err)
	require.Equal(t, "https://example.com", s)

	s, err = ExtractURL([]byte(`{"owner": {"url": "https://a.example", "a/b": "x"}, "list": ["https://l.example"]}`), "json", "/owner/url")
	require.NoError(t, err)
	require.Equal(t, "https://a.example", s)

	s, err = ExtractURL([]byte(`{"owner": {"a/b": "https://slash.example"}}`), "json", "/owner/a~1b")
	require.NoError(t, err)
	require.Equal(t, "https://slash.example", s)

	s, err = ExtractURL([]byte(`{"list": ["https://l.example"]}`), "json", "/list/0")
	require.NoError(t, err)
	require.Equal(t, "https://l.example", s)

	s, err = ExtractURL([]byte("owner:\n  url: https://y.example\n"), "yaml", "/owner/url")
	require.NoError(t, err)
	require.Equal(t, "https://y.example", s)

	_, err = ExtractURL([]byte(`{"owner": {"url": 1}}`), "json", "/owner/url")
	require.ErrorContains(t, err, "want a string")
	_, err = ExtractURL([]byte(`{"owner": {}}`), "json", "/owner/url")
	require.ErrorContains(t, err, "not found")
	_, err = ExtractURL([]byte(`{}`), "json", "owner")
	require.ErrorContains(t, err, "must start with /")
	_, err = ExtractURL([]byte(``), "text", "")
	require.ErrorContains(t, err, "empty")
	_, err = ExtractURL([]byte(`x`), "toml", "")
	require.ErrorContains(t, err, "unknown owner file format")
}

func TestDocumentContextFor(t *testing.T) {
	t.Parallel()
	doc, err := ParseDocument([]byte(`
version: 1
context:
  signers: [global@example.com]
  team: core
paths:
  "data/example.com/":
    context: { signers: [path@example.com] }
repositories:
  github.com/org/registry:
    context: { team: registry }
    paths:
      data/example.com:
        context: { signers: [repopath@example.com] }
`))
	require.NoError(t, err)

	got := doc.ContextFor("", "other/")
	require.Equal(t, []any{"global@example.com"}, got["signers"])
	require.Equal(t, "core", got["team"])

	got = doc.ContextFor("", "data/example.com/")
	require.Equal(t, []any{"path@example.com"}, got["signers"])

	got = doc.ContextFor("github.com/org/registry", "data/example.com/")
	require.Equal(t, []any{"repopath@example.com"}, got["signers"])
	require.Equal(t, "registry", got["team"])

	_, err = ParseDocument([]byte("version: 2\n"))
	require.ErrorContains(t, err, "unsupported owner document version")
	_, err = ParseDocument([]byte("version: 1\nbogus: 1\n"))
	require.ErrorContains(t, err, "bogus")
	_, err = ParseDocument([]byte("   \n"))
	require.ErrorContains(t, err, "empty")
}

func TestProviderFiltersKeys(t *testing.T) {
	t.Parallel()
	p, err := NewProvider(map[string]any{"signers": []any{"a"}, "secret": true, "other": 1}, []string{"signers", "missing"})
	require.NoError(t, err)
	require.Equal(t, []string{"signers"}, p.Keys())
	v, err := p.GetContextValue("secret")
	require.NoError(t, err)
	require.Nil(t, v)
	m, err := p.GetContextMap([]string{"signers", "secret", "other"})
	require.NoError(t, err)
	require.Len(t, m, 1)
	require.Contains(t, m, "signers")

	_, err = NewProvider(map[string]any{"Signers": []any{"a"}}, []string{"signers"})
	require.ErrorIs(t, err, ErrKeyClash)
	_, err = NewProvider(map[string]any{"team": 1, "Team": 2}, []string{"signers"})
	require.ErrorIs(t, err, ErrKeyClash)
}

func TestVerifyDigest(t *testing.T) {
	t.Parallel()
	data := []byte("version: 1\n")
	require.NoError(t, VerifyDigest(data, nil))
	// sha256 of "version: 1\n"
	good := "sha256:3ca0d4bc50d6ad3c9fa6ed9bd0a0e0d9acd8e7cf1de1ec3ec4ad5c9e59b1e0c9"
	require.Error(t, VerifyDigest(data, []string{good}))
	sum := sha256Hex(data)
	require.NoError(t, VerifyDigest(data, []string{"sha256:" + sum}))
	require.NoError(t, VerifyDigest(data, []string{good, "SHA256:" + strings.ToUpper(sum)}))
	require.ErrorContains(t, VerifyDigest(data, []string{"md5:abc"}), "unsupported")
}

func TestResolveHost(t *testing.T) {
	t.Parallel()
	rule := &config.Rule{Path: "data/", Owner: config.Owner{Scheme: config.SchemeHost, WellKnown: "/.well-known/claim.yaml"}}
	o, err := Resolve(&config.Unit{Rule: rule, Path: "data/Example.COM/", Segments: []string{"Example.COM"}}, nil)
	require.NoError(t, err)
	require.Equal(t, KindHTTPS, o.Kind)
	require.Equal(t, "https://example.com/.well-known/claim.yaml", o.String())

	for _, seg := range []string{"localhost", "127.0.0.1", "..", "nodots", "exa mple.com"} {
		_, err := Resolve(&config.Unit{Rule: rule, Path: "data/" + seg + "/", Segments: []string{seg}}, nil)
		require.ErrorIs(t, err, ErrNoOwner, seg)
	}
}

func TestResolveFile(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"vendor/acme/config.json":  `{"owner": {"url": "https://acme.example"}}`,
		"vendor/git/config.json":   `{"owner": {"url": "git+https://github.com/acme/owners@main"}}`,
		"vendor/bad/config.json":   `{"owner": {"url": "http://acme.example"}}`,
		"vendor/local/config.json": `{"owner": {"url": "file:///etc"}}`,
	}
	read := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("not found")
	}
	rule := &config.Rule{Path: "vendor/", Owner: config.Owner{Scheme: config.SchemeFile, File: "config.json", Format: "json", Pointer: "/owner/url"}}

	o, err := Resolve(&config.Unit{Rule: rule, Path: "vendor/acme/", Segments: []string{"acme"}}, read)
	require.NoError(t, err)
	require.Equal(t, "https://acme.example/.well-known/claim.yaml", o.String())
	require.Contains(t, o.Source, "vendor/acme/config.json")

	o, err = Resolve(&config.Unit{Rule: rule, Path: "vendor/git/", Segments: []string{"git"}}, read)
	require.NoError(t, err)
	require.Equal(t, KindGit, o.Kind)
	require.Equal(t, "git+https://github.com/acme/owners@main#claim.yaml", o.String())

	for _, seg := range []string{"bad", "local", "missing"} {
		_, err := Resolve(&config.Unit{Rule: rule, Path: "vendor/" + seg + "/", Segments: []string{seg}}, read)
		require.ErrorIs(t, err, ErrNoOwner, seg)
	}

	// The document setting changes the default file.
	rule2 := *rule
	rule2.Owner.Document = "claim/owners.yaml"
	o, err = Resolve(&config.Unit{Rule: &rule2, Path: "vendor/acme/", Segments: []string{"acme"}}, read)
	require.NoError(t, err)
	require.Equal(t, "https://acme.example/claim/owners.yaml", o.String())
}

func writeString(w http.ResponseWriter, s string) {
	if _, err := io.WriteString(w, s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// routeTransport sends every request to the test server regardless of host.
type routeTransport struct{ target *url.URL }

func (rt *routeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	r2.URL.Scheme = rt.target.Scheme
	r2.URL.Host = rt.target.Host
	r2.Host = rt.target.Host
	return http.DefaultTransport.RoundTrip(r2)
}

func TestFetcherHTTP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/claim.yaml":
			writeString(w, "version: 1\ncontext: {signers: [a]}\n")
		case "/redirect":
			http.Redirect(w, r, "/.well-known/claim.yaml", http.StatusFound)
		case "/big":
			writeString(w, strings.Repeat("x", 2048))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	require.NoError(t, err)
	f := &Fetcher{Transport: &routeTransport{target: target}, MaxSize: 1024}

	mk := func(p string) *Owner {
		u, _, err := ParseOwnerURL("https://owner.example" + p)
		require.NoError(t, err)
		return &Owner{Kind: KindHTTPS, URL: u}
	}
	data, err := f.Fetch(context.Background(), mk("/.well-known/claim.yaml"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(data), "version: 1"))

	_, err = f.Fetch(context.Background(), mk("/missing"))
	require.ErrorContains(t, err, "404")
	_, err = f.Fetch(context.Background(), mk("/redirect"))
	require.ErrorContains(t, err, "redirect")
	_, err = f.Fetch(context.Background(), mk("/big"))
	require.ErrorContains(t, err, "too large")
}

func TestFetcherRefusesPrivate(t *testing.T) {
	t.Parallel()
	// A TLS test server lives on the loopback interface: the guarded dialer
	// must refuse it before any TLS handshake happens.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeString(w, "version: 1\n")
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	// Bypass ParseOwnerURL on purpose: we are testing the dial-time guard.
	u.Host = "localhost:" + u.Port()
	f := &Fetcher{}
	_, err = f.Fetch(context.Background(), &Owner{Kind: KindHTTPS, URL: u})
	require.ErrorContains(t, err, "non-public address")

	// Plain http is refused outright unless AllowPrivate is set.
	plain, err := url.Parse("http://example.com/x")
	require.NoError(t, err)
	_, err = f.Fetch(context.Background(), &Owner{Kind: KindHTTPS, URL: plain})
	require.ErrorContains(t, err, "refusing")

	// Local git repositories are refused as owners unless AllowPrivate is set.
	local, err := url.Parse("file:///tmp/repo#claim.yaml")
	require.NoError(t, err)
	_, err = f.Fetch(context.Background(), &Owner{Kind: KindGit, URL: local})
	require.ErrorContains(t, err, "local repository")
}
