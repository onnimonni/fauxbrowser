package proxy

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type rootCASource struct {
	env  string
	path string
	dir  bool
}

// loadRootCAsFromEnv builds an explicit root pool from the standard
// CA-bundle environment variables commonly used on NixOS/systemd. When
// none are set, it returns nil so the caller can preserve the platform
// default behavior.
func loadRootCAsFromEnv() (*x509.CertPool, []string, error) {
	sources := rootCASourcesFromEnv()
	if len(sources) == 0 {
		return nil, nil, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	loaded := make([]string, 0, len(sources))
	for _, src := range sources {
		var ok bool
		if src.dir {
			ok, err = appendCertsFromDir(pool, src.path)
		} else {
			ok, err = appendCertsFromFile(pool, src.path)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("transport root CAs: %s=%q: %w", src.env, src.path, err)
		}
		if !ok {
			return nil, nil, fmt.Errorf("transport root CAs: %s=%q contained no PEM certificates", src.env, src.path)
		}
		loaded = append(loaded, src.env+"="+src.path)
	}

	return pool, loaded, nil
}

func rootCASourcesFromEnv() []rootCASource {
	var sources []rootCASource
	seen := map[string]struct{}{}

	addFile := func(env string) {
		path := strings.TrimSpace(os.Getenv(env))
		if path == "" {
			return
		}
		key := "file:" + path
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		sources = append(sources, rootCASource{env: env, path: path})
	}

	addDirList := func(env string) {
		for _, dir := range filepath.SplitList(strings.TrimSpace(os.Getenv(env))) {
			dir = strings.TrimSpace(dir)
			if dir == "" {
				continue
			}
			key := "dir:" + dir
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			sources = append(sources, rootCASource{env: env, path: dir, dir: true})
		}
	}

	addFile("NIX_SSL_CERT_FILE")
	addFile("SSL_CERT_FILE")
	addDirList("SSL_CERT_DIR")
	return sources
}

func appendCertsFromDir(pool *x509.CertPool, dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("read dir: %w", err)
	}

	loaded := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ok, err := appendCertsFromFile(pool, filepath.Join(dir, entry.Name()))
		if err != nil {
			return false, err
		}
		loaded = loaded || ok
	}

	return loaded, nil
}

func appendCertsFromFile(pool *x509.CertPool, path string) (bool, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read file: %w", err)
	}
	return pool.AppendCertsFromPEM(pemData), nil
}
