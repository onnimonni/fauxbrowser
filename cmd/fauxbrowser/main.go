// fauxbrowser — TLS fingerprint forging HTTP proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/onnimonni/fauxbrowser/internal/ca"
	"github.com/onnimonni/fauxbrowser/internal/config"
	"github.com/onnimonni/fauxbrowser/internal/proxy"
)

// version is overridden at build time via -ldflags "-X main.version=<sha>".
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.Default()
	cfg.LoadEnv()

	fs := flag.NewFlagSet("fauxbrowser", flag.ExitOnError)
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "address to listen on (e.g. 127.0.0.1:18443)")
	fs.StringVar(&cfg.AdminListen, "admin-listen", cfg.AdminListen, "optional admin listener for /healthz (empty = disabled)")
	fs.StringVar(&cfg.Upstream, "upstream", cfg.Upstream, "upstream HTTP proxy URL (empty = direct)")
	fs.StringVar(&cfg.Profile, "profile", cfg.Profile, "default browser profile (e.g. chrome146)")
	fs.StringVar(&cfg.CACertPath, "ca-cert", cfg.CACertPath, "path to existing CA cert PEM")
	fs.StringVar(&cfg.CAKeyPath, "ca-key", cfg.CAKeyPath, "path to existing CA private key PEM")
	fs.StringVar(&cfg.CAOut, "ca-out", cfg.CAOut, "persist auto-generated CA to basename.pem + .key")
	fs.StringVar(&cfg.TargetHeader, "target-header", cfg.TargetHeader, "header name carrying the target URL in header mode")
	fs.IntVar(&cfg.TimeoutSecs, "timeout", cfg.TimeoutSecs, "per-request upstream timeout seconds")
	fs.StringVar(&cfg.Auth, "auth", cfg.Auth, "Proxy-Authorization Basic user:pass (required for non-loopback without -allow-open)")
	var allowHostsFlag string
	fs.StringVar(&allowHostsFlag, "allow-hosts", strings.Join(cfg.AllowHosts, ","), "comma-separated host glob allow-list")
	fs.BoolVar(&cfg.AllowOpen, "allow-open", cfg.AllowOpen, "allow non-loopback listen without auth (dangerous)")
	fs.IntVar(&cfg.LeafCacheMax, "leaf-cache-max", cfg.LeafCacheMax, "max cached MITM leaf certs")
	fs.IntVar(&cfg.SessionMax, "session-max", cfg.SessionMax, "max concurrent tls-client sessions in pool")
	fs.BoolVar(&cfg.Insecure, "insecure", cfg.Insecure, "skip upstream TLS verification (tests only)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug|info|warn|error")
	showVersion := fs.Bool("version", false, "print version and exit")
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Println("fauxbrowser", version)
		return nil
	}

	if allowHostsFlag != "" {
		cfg.AllowHosts = config.SplitCSV(allowHostsFlag)
	}

	setupLogger(cfg.LogLevel)

	// Safety: refuse to bind non-loopback without auth unless -allow-open.
	if err := safetyCheck(cfg); err != nil {
		return err
	}

	// CA bootstrap.
	pair, err := bootstrapCA(cfg)
	if err != nil {
		return err
	}
	leafCache := ca.NewLeafCache(pair, cfg.LeafCacheMax)

	// Transport (tls-client pool).
	transport := proxy.NewTransport(proxy.TransportOptions{
		DefaultProfile: cfg.Profile,
		UpstreamProxy:  cfg.Upstream,
		TimeoutSeconds: cfg.TimeoutSecs,
		Insecure:       cfg.Insecure,
		ProfileHeader:  cfg.ProfileHdr,
		SessionHeader:  cfg.SessionHdr,
		MaxSessions:    cfg.SessionMax,
	})
	defer transport.Close()

	mitm := proxy.NewMITM(leafCache, transport)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mitm.Shutdown(ctx)
	}()

	handler := proxy.NewHandler(proxy.Options{
		ListenAddr:   cfg.Listen,
		TargetHeader: cfg.TargetHeader,
		Transport:    transport,
		MITM:         mitm,
	})
	handler = proxy.HostAllowList(handler, cfg.AllowHosts, cfg.TargetHeader)
	handler = proxy.BasicAuth(handler, cfg.Auth)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}

	upstreamDesc := cfg.Upstream
	if upstreamDesc == "" {
		upstreamDesc = "(direct)"
	}
	slog.Info("fauxbrowser ready",
		"version", version,
		"listen", cfg.Listen,
		"upstream", upstreamDesc,
		"profile", cfg.Profile,
		"auth", cfg.Auth != "",
		"allow_hosts", cfg.AllowHosts,
	)

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Optional admin listener for /healthz.
	var adminSrv *http.Server
	if cfg.AdminListen != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
		adminSrv = &http.Server{Addr: cfg.AdminListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("admin listener", "err", err)
			}
		}()
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		slog.Info("shutdown signal received, draining (15s max)")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("main shutdown", "err", err)
	}
	if adminSrv != nil {
		_ = adminSrv.Shutdown(shutdownCtx)
	}
	return nil
}

func bootstrapCA(cfg *config.Config) (*ca.Pair, error) {
	if cfg.CACertPath != "" && cfg.CAKeyPath != "" {
		pair, err := ca.Load(cfg.CACertPath, cfg.CAKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load CA: %w", err)
		}
		slog.Info("loaded CA", "cert", cfg.CACertPath, "key", cfg.CAKeyPath)
		return pair, nil
	}
	pair, err := ca.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}
	slog.Warn("generated ephemeral CA — set -ca-cert/-ca-key for persistence")
	if cfg.CAOut != "" {
		if err := pair.Write(cfg.CAOut); err != nil {
			return nil, fmt.Errorf("write CA: %w", err)
		}
		slog.Info("CA persisted", "cert", cfg.CAOut+".pem", "key", cfg.CAOut+".key")
	}
	return pair, nil
}

func safetyCheck(cfg *config.Config) error {
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("invalid -listen: %w", err)
	}
	loopback := host == "" || host == "127.0.0.1" || host == "::1" || host == "localhost"
	if loopback {
		return nil
	}
	if cfg.Auth != "" {
		return nil
	}
	if cfg.AllowOpen {
		slog.Warn("listening on non-loopback without auth (-allow-open set)", "listen", cfg.Listen)
		return nil
	}
	return fmt.Errorf("refusing to listen on non-loopback %q without -auth or -allow-open", cfg.Listen)
}

func setupLogger(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
}
