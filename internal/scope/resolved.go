package scope

import (
	"net/netip"
	"strings"
	"time"
)

// ResolvableHost returns the hostname of a target that is a name (a bare host, host:port or a URL
// whose host is a name). IPs, CIDRs and unparseable targets return ok=false: they need no DNS.
func ResolvableHost(target string) (string, bool) {
	p, ok := parseTarget(target)
	if !ok || p.isIP || p.isCIDR || p.host == "" {
		return "", false
	}
	return p.host, true
}

// IsBlockedAddr reports addresses that are never reached through a name unless the scope
// explicitly includes them: loopback, private (RFC 1918 / ULA), link-local (including the cloud
// metadata address 169.254.169.254), CGNAT, unspecified, multicast and IPv4 special ranges.
func IsBlockedAddr(a netip.Addr) bool {
	a = canonAddr(a)
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "fd00:ec2::254/128"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// EvaluateResolved is Evaluate plus the addresses the target's hostname resolved to (resolved by
// the caller; this function performs no I/O). A name that is IN_SCOPE by name is downgraded to
// OUT_OF_SCOPE when any resolved address
//
//   - matches an excluded IP/CIDR rule, or
//   - is a blocked/internal address (see IsBlockedAddr) that no included IP/CIDR rule covers.
//
// Public addresses that no IP/CIDR rule mentions are left to the name decision. With no addresses
// (resolution failed or not attempted) the result equals Evaluate.
func EvaluateResolved(s *Scope, target string, now time.Time, ips []netip.Addr) Decision {
	d := Evaluate(s, target, now)
	if d.Result != InScope || len(ips) == 0 {
		return d
	}
	if _, isName := ResolvableHost(target); !isName {
		return d
	}
	for _, raw := range ips {
		a := canonAddr(raw)
		p := parsed{isIP: true, addr: a}
		for _, r := range s.excluded {
			if (r.kind == kindIP || r.kind == kindCIDR) && r.matches(p) {
				return Decision{Result: OutOfScope, Target: target,
					Reason: "resolves to out-of-scope address " + a.String() + " (excluded " + r.raw + ")"}
			}
		}
		if IsBlockedAddr(a) {
			included := false
			for _, r := range s.included {
				if (r.kind == kindIP || r.kind == kindCIDR) && r.matches(p) {
					included = true
					break
				}
			}
			if !included {
				return Decision{Result: OutOfScope, Target: target,
					Reason: "resolves to out-of-scope address " + a.String() + " (internal address not included in scope)"}
			}
		}
	}
	return d
}

// IsResolvedRefusal reports whether a reason came from the resolved-address check.
func IsResolvedRefusal(reason string) bool {
	return strings.HasPrefix(reason, "resolves to out-of-scope address")
}
