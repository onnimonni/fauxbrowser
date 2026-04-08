package proxy

import "testing"

func TestIsSelfHost(t *testing.T) {
	tests := []struct {
		name        string
		h           string
		listenHost  string
		listenAddr  string
		want        bool
	}{
		{"exact match full addr", "127.0.0.1:18443", "127.0.0.1", "127.0.0.1:18443", true},
		{"same host different port = different service", "127.0.0.1:9999", "127.0.0.1", "127.0.0.1:18443", false},
		{"bare same host", "127.0.0.1", "127.0.0.1", "127.0.0.1:18443", true},
		{"wildcard listen + loopback different port", "127.0.0.1:8080", "", "0.0.0.0:18443", false},
		{"wildcard listen + localhost", "localhost", "0.0.0.0", "0.0.0.0:18443", true},
		{"wildcard listen + ::1", "::1", "0.0.0.0", "0.0.0.0:18443", true},
		{"real target host", "www.proshop.dk", "127.0.0.1", "127.0.0.1:18443", false},
		{"real target with port", "www.proshop.dk:443", "127.0.0.1", "127.0.0.1:18443", false},
		{"empty", "", "127.0.0.1", "127.0.0.1:18443", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsSelfHost(tc.h, tc.listenHost, tc.listenAddr)
			if got != tc.want {
				t.Errorf("IsSelfHost(%q,%q,%q) = %v, want %v",
					tc.h, tc.listenHost, tc.listenAddr, got, tc.want)
			}
		})
	}
}
