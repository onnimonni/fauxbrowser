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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/onnimonni/fauxbrowser/internal/config"
	"github.com/onnimonni/fauxbrowser/internal/proton"
	"github.com/onnimonni/fauxbrowser/internal/proxy"
	"github.com/onnimonni/fauxbrowser/internal/rotator"
	"github.com/onnimonni/fauxbrowser/internal/solver"
	chromedpsolver "github.com/onnimonni/fauxbrowser/internal/solver/chromedp"
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
	fs.StringVar(&cfg.WGPrivateKey, "wg-private-key", cfg.WGPrivateKey, "base64 WireGuard private key (alternative to -wg-conf; gluetun-style)")
	fs.StringVar(&cfg.VPNTier, "vpn-tier", cfg.VPNTier, "server tier: free (default), paid|plus, or all")
	fs.StringVar(&cfg.Profile, "profile", cfg.Profile, "browser profile: chrome146 (default), chrome144, chrome133, chrome131, or 'latest'")
	fs.StringVar(&cfg.Solver, "solver", cfg.Solver, "WAF challenge solver: none (default — single binary, no Chromium dep) or chromedp (launches headless Chromium on demand)")
	fs.DurationVar(&cfg.SolverTTL, "solver-ttl", cfg.SolverTTL, "how long to cache a solved (host, exit_ip) cookie bundle")
	fs.DurationVar(&cfg.SolverTimeout, "solver-timeout", cfg.SolverTimeout, "max time per Chromium solve (startup + navigation + extract)")
	fs.StringVar(&cfg.ChromiumPath, "chromium-path", cfg.ChromiumPath, "absolute Chromium binary path (default = $PATH lookup)")
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

	// Either -wg-conf (a wg-quick file path) or -wg-private-key
	// (gluetun-style env, just the base64 key) is required.
	if cfg.WGConf == "" && cfg.WGPrivateKey == "" {
		return errors.New("either -wg-conf or -wg-private-key (or WIREGUARD_PRIVATE_KEY env) is required")
	}
	var (
		baseCfg *wgtunnel.Config
		err     error
	)
	if cfg.WGConf != "" {
		baseCfg, err = wgtunnel.LoadConfig(cfg.WGConf)
		if err != nil {
			return fmt.Errorf("load wg conf: %w", err)
		}
	} else {
		baseCfg, err = wgtunnel.ConfigFromPrivateKey(cfg.WGPrivateKey)
		if err != nil {
			return fmt.Errorf("parse wg private key: %w", err)
		}
		slog.Info("WireGuard interface bootstrapped from private key only",
			"address", "10.2.0.2/32", "dns", "10.2.0.1")
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

	// Optional WAF challenge solver. Built BEFORE the rotator so the
	// rotator's OnRotate hook can call cache.InvalidateExit on the
	// outgoing exit IP — clearance cookies are exit-IP-bound and
	// must be dropped on rotation.
	var solverCache *solver.Cache
	switch strings.ToLower(cfg.Solver) {
	case "", "none":
		// disabled — fauxbrowser stays single-binary, no Chromium dep
	case "chromedp":
		if !chromedpsolver.ChromiumAvailable(cfg.ChromiumPath) {
			return fmt.Errorf("-solver chromedp: no Chromium binary on PATH (or at -chromium-path); install chromium / google-chrome / chrome and retry")
		}
		profile := proxy.SelectProfile(cfg.Profile)
		ch := chromedpsolver.New(chromedpsolver.Options{
			UpstreamProxy: "http://" + cfg.Listen,
			UserAgent:     profile.UserAgent,
			SolveTimeout:  cfg.SolverTimeout,
			ChromiumPath:  cfg.ChromiumPath,
			Logf:          func(msg string, args ...any) { slog.Info(msg, args...) },
		})
		solverCache = solver.NewCache(ch, cfg.SolverTTL)
		slog.Info("WAF challenge solver enabled",
			"solver", "chromedp", "ttl", cfg.SolverTTL.String(),
			"timeout", cfg.SolverTimeout.String())
	default:
		return fmt.Errorf("-solver %q: unknown solver (valid: none, chromedp)", cfg.Solver)
	}

	var transport *proxy.Transport
	// Track the previous exit IP across rotations so the OnRotate
	// hook knows which IP to invalidate in the solver cache.
	var prevExitIP atomic.Pointer[string]
	emptyIP := ""
	prevExitIP.Store(&emptyIP)

	var rot *rotator.Rotator
	rot = rotator.New(rotator.Options{
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
			// Solver cache cookies are bound to the (UA, exit_ip)
			// tuple — must drop everything for the OLD exit IP on
			// rotation.
			if solverCache != nil {
				oldIP := *prevExitIP.Load()
				if oldIP != "" {
					dropped := solverCache.InvalidateExit(oldIP)
					if dropped > 0 {
						slog.Info("solver: cache invalidated for old exit IP",
							"old_ip", oldIP, "dropped", dropped)
					}
				}
			}
			// Snapshot the new exit IP for the next rotation event.
			newIP := rot.Stats().CurrentIP
			prevExitIP.Store(&newIP)
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
		SolverCache:    solverCache,
		ExitIPProvider: func() string { return rot.Stats().CurrentIP },
	})
	if err != nil {
		return fmt.Errorf("build transport: %w", err)
	}
	defer transport.Close()

	base := proxy.NewHandler(proxy.Options{
		TargetHeader: cfg.TargetHeader,
		Transport:    transport,
		// Same dialer used by the Transport — routes through the
		// current WireGuard tunnel and honors per-host quarantine.
		// CONNECT tunnels go through this directly, bypassing
		// tls-client (the client speaks its own TLS to the target).
		Dialer: rot.Dialer(),
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
