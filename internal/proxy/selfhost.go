package proxy

import "net"

// IsSelfHost reports whether h refers to the proxy's own listener, i.e.
// the client is accidentally asking the proxy to fetch itself.
//
// Only a full host:port match against listenAddr, or a bareword host
// match against listenHost (no port — implicitly the same service),
// counts as "self". A different port on the same IP is a different
// service and is NOT self.
func IsSelfHost(h, listenHost, listenAddr string) bool {
	if h == "" {
		return true
	}
	if h == listenAddr {
		return true
	}
	hh, _, err := net.SplitHostPort(h)
	if err == nil {
		// Different port = different service, even if the IP matches.
		return false
	}
	hh = h // no port in h
	if hh == listenHost {
		return true
	}
	if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" {
		if hh == "localhost" || hh == "127.0.0.1" || hh == "::1" {
			return true
		}
		if ip := net.ParseIP(hh); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}
