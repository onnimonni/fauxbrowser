// fauxbrowser — single-binary HTTP proxy that forwards to targets over
// an embedded ProtonVPN free-tier WireGuard tunnel, forges a chrome146
// TLS fingerprint on the way out, and rotates the exit IP when the
// downstream target rate-limits or WAF-challenges us.
package main

import (
	"context"
	"encoding/json"
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

	"github.com/onnimonni/fauxbrowser/internal/config"
	"github.com/onnimonni/fauxbrowser/internal/proton"
	"github.com/onnimonni/fauxbrowser/internal/proxy"
	"github.com/onnimonni/fauxbrowser/internal/rotator"
	"github.com/onnimonni/fauxbrowser/internal/wgtunnel"
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
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "plaintext h2c listen address")
	fs.StringVar(&cfg.AdminListen, "admin-listen", cfg.AdminListen, "optional admin listener (/healthz, /rotate)")
	fs.StringVar(&cfg.WGConf, "wg-conf", cfg.WGConf, "path to a wg-quick .conf (only PrivateKey + Address/DNS are used; peer is picked from the Proton catalog)")
	fs.StringVar(&cfg.VPNTier, "vpn-tier", cfg.VPNTier, "server tier: free (default), paid|plus, or all")
	fs.StringVar(&cfg.Profile, "profile", cfg.Profile, "browser profile: chrome146 (default), chrome144, chrome133, chrome131, or 'latest'")
	var countriesFlag string
	fs.StringVar(&countriesFlag, "vpn-country", strings.Join(cfg.VPNCountries, ","), "comma-separated ISO country allow-list (e.g. NL,DE)")
	var continentsFlag string
	fs.StringVar(&continentsFlag, "vpn-continent", strings.Join(cfg.VPNContinents, ","), "comma-separated continent allow-list (EU,NA,AS,OC,SA,AF)")
	fs.IntVar(&cfg.TimeoutSecs, "timeout", cfg.TimeoutSecs, "per-request upstream timeout seconds")
	fs.IntVar(&cfg.CooldownSecs, "cooldown", cfg.CooldownSecs, "taint cooldown for a burned exit IP, seconds")
	fs.DurationVar(&cfg.HandshakeWait, "handshake-wait", cfg.HandshakeWait, "max time to wait for a WireGuard handshake per rotation attempt")
	fs.DurationVar(&cfg.MinHostRotation, "host-debounce", cfg.MinHostRotation, "per-host rotation debounce (second 429 on the same host within this window → no re-rotation, upstream status passes through)")
	fs.DurationVar(&cfg.GlobalMinInterval, "rotation-min-interval", cfg.GlobalMinInterval, "global minimum interval between any two rotations")
	fs.DurationVar(&cfg.MaxRetireAge, "retire-max-age", cfg.MaxRetireAge, "force-close retired tunnels with in-flight > 0 after this age")
	fs.DurationVar(&cfg.ReaperInterval, "reaper-interval", cfg.ReaperInterval, "how often the reaper scans for drained tunnels")
	fs.StringVar(&cfg.AuthToken, "auth-token", cfg.AuthToken, "bearer token required on the proxy listener (mandatory on non-loopback binds)")
	fs.StringVar(&cfg.AdminToken, "admin-token", cfg.AdminToken, "bearer token required on the admin listener (mandatory on non-loopback binds)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug|info|warn|error")
	showVersion := fs.Bool("version", false, "print version and exit")
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Println("fauxbrowser", version)
		return nil
	}
	if countriesFlag != "" {
		cfg.VPNCountries = config.SplitCSV(countriesFlag)
	}
	if continentsFlag != "" {
		cfg.VPNContinents = config.SplitCSV(continentsFlag)
	}

	setupLogger(cfg.LogLevel)

	if err := safetyCheck(cfg); err != nil {
		return err
	}

	if cfg.WGConf == "" {
		return errors.New("-wg-conf is required (path to a Proton .conf with PrivateKey + Address/DNS)")
	}
	baseCfg, err := wgtunnel.LoadConfig(cfg.WGConf)
	if err != nil {
		return fmt.Errorf("load wg conf: %w", err)
	}
	// The base conf's peer fields are DISCARDED — rotator picks peers
	// from the Proton catalog. Wipe them to make that invariant loud.
	baseCfg.PeerPublicKey = nil
	baseCfg.PeerPresharedKey = nil
	baseCfg.EndpointHost = ""
	baseCfg.EndpointPort = 0

	catalog, err := proton.Embedded()
	if err != nil {
		return fmt.Errorf("load proton catalog: %w", err)
	}
	tierFilter := proton.ParseTierFilter(cfg.VPNTier)
	servers := catalog.Filter(tierFilter, cfg.VPNCountries, cfg.VPNContinents)
	if len(servers) == 0 {
		return fmt.Errorf("no Proton servers match tier=%s countries=%v continents=%v",
			cfg.VPNTier, cfg.VPNCountries, cfg.VPNContinents)
	}
	slog.Info("proton catalog loaded",
		"total", catalog.Len(),
		"filtered", len(servers),
		"tier", cfg.VPNTier,
		"countries", cfg.VPNCountries,
		"continents", cfg.VPNContinents,
		"snapshot", catalog.FetchedAt())

	pool := proton.NewPool(servers, int64(cfg.CooldownSecs), nil)

	var transport *proxy.Transport
	rot := rotator.New(rotator.Options{
		BaseConfig:        baseCfg,
		Catalog:           catalog,
		Pool:              pool,
		HandshakeTimeout:  cfg.HandshakeWait,
		MinHostRotation:   cfg.MinHostRotation,
		GlobalMinInterval: cfg.GlobalMinInterval,
		MaxRetireAge:      cfg.MaxRetireAge,
		ReaperInterval:    cfg.ReaperInterval,
		OnRotate: func() {
			// After the swap, clear our internal cookie jar so no
			// Set-Cookie from the old IP can leak into a request sent
			// via the new IP. Caller-set Cookie headers on incoming
			// requests are untouched.
			if transport != nil {
				if err := transport.RotateJar(); err != nil {
					slog.Warn("rotator: jar rebuild failed", "err", err)
				}
			}
		},
		Logf: func(msg string, args ...any) { slog.Info(msg, args...) },
	})
	defer rot.Close()

	bootstrapCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	if err := rot.Bootstrap(bootstrapCtx); err != nil {
		cancel()
		return fmt.Errorf("bring up initial tunnel: %w", err)
	}
	cancel()

	transport, err = proxy.NewTransport(proxy.TransportOptions{
		Dialer:         rot.Dialer(),
		TimeoutSeconds: cfg.TimeoutSecs,
		Profile:        cfg.Profile,
		Rotator:        rot,
	})
	if err != nil {
		return fmt.Errorf("build transport: %w", err)
	}
	defer transport.Close()

	base := proxy.NewHandler(proxy.Options{
		TargetHeader: cfg.TargetHeader,
		Transport:    transport,
	})
	// BearerAuth is a no-op when AuthToken is empty (loopback default).
	// When bound to a non-loopback, safetyCheck has already refused to
	// start without a token, so auth here is always enforced.
	handler := proxy.WrapH2C(proxy.BearerAuth(base, cfg.AuthToken))

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}

	slog.Info("fauxbrowser ready",
		"version", version,
		"listen", cfg.Listen,
		"exit_ip", rot.Stats().CurrentIP,
		"pool_size", pool.Size())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var adminSrv *http.Server
	if cfg.AdminListen != "" {
		adminSrv = startAdmin(cfg.AdminListen, cfg.AdminToken, rot)
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

	shutdownCtx, shCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shCancel()
	_ = srv.Shutdown(shutdownCtx)
	if adminSrv != nil {
		_ = adminSrv.Shutdown(shutdownCtx)
	}
	return nil
}

func startAdmin(addr, token string, rot *rotator.Rotator) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rot.Stats())
	})
	mux.HandleFunc("/rotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		if err := rot.ForceRotate(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rot.Stats())
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           proxy.BearerAuth(mux, token),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("admin listener", "err", err)
		}
	}()
	return srv
}

// safetyCheck refuses to start when a listener is bound to a non-
// loopback interface without a bearer token set. Loopback binds stay
// auth-free by default — that's the expected single-operator use case.
func safetyCheck(cfg *config.Config) error {
	if isNonLoopback(cfg.Listen) {
		if cfg.AuthToken == "" {
			return fmt.Errorf("-listen %q is non-loopback; -auth-token (or FAUXBROWSER_AUTH_TOKEN) is mandatory", cfg.Listen)
		}
		slog.Warn("proxy listener bound to non-loopback — bearer auth enforced", "listen", cfg.Listen)
	}
	if cfg.AdminListen != "" && isNonLoopback(cfg.AdminListen) {
		if cfg.AdminToken == "" {
			return fmt.Errorf("-admin-listen %q is non-loopback; -admin-token (or FAUXBROWSER_ADMIN_TOKEN) is mandatory", cfg.AdminListen)
		}
		slog.Warn("admin listener bound to non-loopback — bearer auth enforced", "admin-listen", cfg.AdminListen)
	}
	return nil
}

// isNonLoopback returns true for any listen address that is not a
// loopback interface. Fails safe: unparseable addresses are treated
// as non-loopback so the auth requirement kicks in.
func isNonLoopback(addr string) bool {
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if host == "" || host == "localhost" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	// Hostname that isn't "localhost" — assume non-loopback.
	return true
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
