// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package owner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// schemeHTTPS is the only transport owner documents travel over.
const schemeHTTPS = "https"

// Kind is the kind of owner URL.
type Kind string

const (
	// KindHTTPS is an https URL serving the owner document directly.
	KindHTTPS Kind = "https"
	// KindGit is a git+https VCS locator pointing at the owner document in a
	// repository.
	KindGit Kind = "git"
)

// ErrInvalidHost is returned when a segment or URL host is not an acceptable
// public host name.
var ErrInvalidHost = errors.New("invalid owner host")

// ValidateHostname checks that s is a syntactically valid DNS host name
// (RFC 1123 labels, at least two labels, no IP literal, no port, no
// userinfo). The owner host is derived from data controlled by the pull
// request author, so this is the first line of defense against pointing
// claim at internal or spoofed endpoints.
func ValidateHostname(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty host", ErrInvalidHost)
	}
	if len(s) > 253 {
		return fmt.Errorf("%w: %q is too long", ErrInvalidHost, s)
	}
	if strings.ContainsAny(s, "/:@?#[]\\ \t\r\n%") {
		return fmt.Errorf("%w: %q contains forbidden characters", ErrInvalidHost, s)
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return fmt.Errorf("%w: %q is an IP address, a host name is required", ErrInvalidHost, s)
	}
	// Internationalized names are converted to their ASCII (punycode) form
	// with the strict lookup profile, which also rejects most homoglyph
	// tricks and invalid labels. Anything left that is not ASCII is refused.
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrInvalidHost, s, err)
	}
	for i := range len(ascii) {
		if ascii[i] >= 0x80 {
			return fmt.Errorf("%w: %q has non-ASCII characters", ErrInvalidHost, s)
		}
	}
	host := strings.TrimSuffix(ascii, ".")
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: %q must have at least two labels", ErrInvalidHost, s)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("%w: %q has an empty or oversized label", ErrInvalidHost, s)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%w: label %q starts or ends with a hyphen", ErrInvalidHost, l)
		}
		for i := range len(l) {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return fmt.Errorf("%w: label %q has an invalid character", ErrInvalidHost, l)
			}
		}
	}
	// A purely numeric TLD is never a valid public host.
	tld := labels[len(labels)-1]
	if strings.Trim(tld, "0123456789") == "" {
		return fmt.Errorf("%w: %q has a numeric top level label", ErrInvalidHost, s)
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") ||
		strings.HasSuffix(strings.ToLower(host), ".local") || strings.HasSuffix(strings.ToLower(host), ".internal") {
		return fmt.Errorf("%w: %q is a local name", ErrInvalidHost, s)
	}
	return nil
}

// IsPublicIP reports whether ip is a routable public unicast address. Loopback,
// private, link-local, multicast, unspecified and documentation ranges are
// rejected so that an owner host can never resolve to something inside the
// network claim runs in.
func IsPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	switch {
	case !addr.IsValid(), addr.IsUnspecified(), addr.IsLoopback(), addr.IsPrivate(),
		addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast():
		return false
	}
	for _, cidr := range []string{
		"100.64.0.0/10",   // shared address space (CGNAT)
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved
		"2001:db8::/32",   // documentation
		"64:ff9b::/96",    // NAT64
		"100::/64",        // discard
	} {
		p := netip.MustParsePrefix(cidr)
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// VerifyDigest checks data against a list of pinned digests in
// algo:hex form. Only sha256 is supported. An empty list always passes.
func VerifyDigest(data []byte, digests []string) error {
	if len(digests) == 0 {
		return nil
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	for _, d := range digests {
		algo, val, ok := strings.Cut(strings.TrimSpace(d), ":")
		if !ok || !strings.EqualFold(algo, "sha256") {
			return fmt.Errorf("unsupported pinned digest %q (want sha256:<hex>)", d)
		}
		if strings.EqualFold(val, got) {
			return nil
		}
	}
	return fmt.Errorf("owner document digest sha256:%s matches none of the pinned digests", got)
}

// ParseOwnerURL validates a string extracted from the repository (or derived
// from a path) as an owner URL. Accepted forms are https://host/path and
// git+https://host/org/repo[@ref][#path] VCS locators. Anything else
// (http, file, ssh, embedded credentials, ports, IP literals) is rejected.
func ParseOwnerURL(s string) (*url.URL, Kind, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, "", errors.New("empty owner URL")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return nil, "", fmt.Errorf("owner URL %q contains whitespace", s)
	}
	kind := KindHTTPS
	raw := s
	if strings.HasPrefix(strings.ToLower(s), "git+https://") {
		kind = KindGit
		raw = schemeHTTPS + "://" + s[len("git+https://"):]
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "", fmt.Errorf("parsing owner URL %q: %w", s, err)
	}
	if u.Scheme != schemeHTTPS {
		return nil, "", fmt.Errorf("owner URL %q: scheme %q not allowed (https or git+https)", s, u.Scheme)
	}
	if u.User != nil {
		return nil, "", fmt.Errorf("owner URL %q must not carry credentials", s)
	}
	if u.Port() != "" {
		return nil, "", fmt.Errorf("owner URL %q must not specify a port", s)
	}
	if err := ValidateHostname(u.Hostname()); err != nil {
		return nil, "", fmt.Errorf("owner URL %q: %w", s, err)
	}
	if strings.Contains(u.Path, "..") {
		return nil, "", fmt.Errorf("owner URL %q must not contain '..'", s)
	}
	if kind == KindGit {
		// A locator needs at least org/repo.
		if len(strings.Split(strings.Trim(u.Path, "/"), "/")) < 2 {
			return nil, "", fmt.Errorf("owner locator %q must point to a repository", s)
		}
		if u.RawQuery != "" {
			return nil, "", fmt.Errorf("owner locator %q must not have a query string", s)
		}
	}
	return u, kind, nil
}
