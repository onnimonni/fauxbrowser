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
	fs.StringVar(&cfg.AdminListen, "admin-listen", cfg.AdminListen, "optional admin listener (GET /.internal/healthz, GET /.internal/solver, POST /.internal/rotate)")
	fs.StringVar(&cfg.WGConf, "wg-conf", cfg.WGConf, "path to a wg-quick .conf (only PrivateKey + Address/DNS are used; peer is picked from the Proton catalog)")
	fs.StringVar(&cfg.WGPrivateKey, "wg-private-key", cfg.WGPrivateKey, "base64 WireGuard private key (alternative to -wg-conf; gluetun-style)")
	fs.StringVar(&cfg.VPNTier, "vpn-tier", cfg.VPNTier, "server tier: free (default), paid|plus, or all")
	fs.StringVar(&cfg.Profile, "profile", cfg.Profile, "browser profile: chrome146 (default), chrome144, chrome133, chrome131, or 'latest'")
	fs.StringVar(&cfg.Solver, "solver", cfg.Solver, "WAF challenge solver: none (default — single binary, no Chromium dep) or chromedp (launches headless Chromium on demand)")
	fs.DurationVar(&cfg.SolverTTL, "solver-ttl", cfg.SolverTTL, "how long to cache a solved (host, exit_ip) cookie bundle")
	fs.DurationVar(&cfg.SolverTimeout, "solver-timeout", cfg.SolverTimeout, "max time per Chromium solve (startup + navigation + extract)")
	fs.StringVar(&cfg.ChromiumPath, "chromium-path", cfg.ChromiumPath, "absolute Chromium binary path (default = $PATH lookup)")
	fs.StringVar(&cfg.CookieStorePath, "cookie-store", cfg.CookieStorePath, "directory for persisting CF cookie cache — one file per (host, exitIP), survives restarts (empty = in-memory only)")
	fs.BoolVar(&cfg.AllowVersionMismatch, "allow-version-mismatch", cfg.AllowVersionMismatch,
		"start even if chromedp solver's Chromium has a Chrome major version that has no matching tls-client profile "+
			"(or disagrees with an explicit -profile). Use when nixpkgs chromium just got bumped to N+1 and bogdanfinn/tls-client "+
			"hasn't shipped chromeN+1 yet — solver and fast-path TLS fingerprints will differ, cookie portability on JA3-pinning WAFs is at risk")
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
	//
	// When the solver is enabled we ALSO detect chromium's Chrome
	// major version and reconcile it against the requested profile.
	// A mismatch means the solver's ClientHello and the fast-path
	// ClientHello differ by at least a major version — cookies that
	// are JA3-pinned by the WAF (some aggressive Cloudflare customers
	// bind cf_clearance to the solving browser's TLS fingerprint)
	// will not port from the solver to the fast path. We refuse to
	// start in that case unless the operator explicitly passes
	// -allow-version-mismatch.
	var solverCache *solver.Cache
	var chromiumMajor int
	switch strings.ToLower(cfg.Solver) {
	case "", "none":
		// disabled — fauxbrowser stays single-binary, no Chromium dep
	case "chromedp":
		if !chromedpsolver.ChromiumAvailable(cfg.ChromiumPath) {
			return fmt.Errorf("-solver chromedp: no Chromium binary on PATH (or at -chromium-path); install chromium / google-chrome / chrome and retry")
		}
		m, err := chromedpsolver.DetectChromiumMajor(cfg.ChromiumPath)
		if err != nil {
			return fmt.Errorf("-solver chromedp: detect chromium version: %w", err)
		}
		chromiumMajor = m
		slog.Info("solver: chromium detected", "chrome_major", m, "path", cfg.ChromiumPath)
	default:
		return fmt.Errorf("-solver %q: unknown solver (valid: none, chromedp)", cfg.Solver)
	}

	// Reconcile the browser profile against the detected chromium
	// major (if any). When no solver is active, chromiumMajor=0 and
	// the reconciler is a no-op pass-through to SelectProfile.
	resolvedProfile, err := proxy.ReconcileProfile(cfg.Profile, chromiumMajor, cfg.AllowVersionMismatch)
	if err != nil {
		return err
	}
	cfg.Profile = resolvedProfile

	if chromiumMajor > 0 {
		profile := proxy.SelectProfile(cfg.Profile)
		ch := chromedpsolver.New(chromedpsolver.Options{
			UpstreamProxy: "http://" + cfg.Listen,
			UserAgent:     profile.UserAgent,
			SolveTimeout:  cfg.SolverTimeout,
			ChromiumPath:  cfg.ChromiumPath,
			Logf:          func(msg string, args ...any) { slog.Info(msg, args...) },
		})
		solverCache = solver.NewCache(ch, cfg.SolverTTL)
		// Restore persisted cookies from a previous run and enable
		// auto-persist for every future solve/invalidation.
		if cfg.CookieStorePath != "" {
			solverCache.SetStoreDir(cfg.CookieStorePath)
			if n, err := solverCache.LoadFromDir(cfg.CookieStorePath); err != nil {
				if !os.IsNotExist(err) {
					slog.Warn("solver: could not load cookie store", "dir", cfg.CookieStorePath, "err", err)
				}
			} else if n > 0 {
				slog.Info("solver: restored cookies from disk", "dir", cfg.CookieStorePath, "loaded", n)
			}
		}
		slog.Info("WAF challenge solver enabled",
			"solver", "chromedp",
			"profile", profile.Name,
			"chromium_major", chromiumMajor,
			"ttl", cfg.SolverTTL.String(),
			"timeout", cfg.SolverTimeout.String(),
			"cookie_store", cfg.CookieStorePath)
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
			// After the swap, clear our internal tls-client cookie
			// jar (Set-Cookie from upstream) so stale non-CF session
			// cookies don't leak to the new IP. Caller-set Cookie
			// headers on incoming requests are untouched.
			if transport != nil {
				if err := transport.RotateJar(); err != nil {
					slog.Warn("rotator: jar rebuild failed", "err", err)
				}
			}
			// Solver cache cookies (cf_clearance, _abck, etc.) are
			// PRESERVED across rotations. They're keyed by (host,
			// exitIP) — if the pool cycles back to the same IP
			// later, the cached cookies are ready. Cookies are only
			// invalidated when a CF-specific 403 rejects them
			// (handled by transport's MarkRetryFailed + Invalidate).
			//
			// Snapshot the new exit IP for the next rotation event.
			newIP := rot.Stats().CurrentIP
			prevExitIP.Store(&newIP)

			// Full sync to disk on rotation in case new entries
			// were added since the last per-entry auto-persist.
			if solverCache != nil && cfg.CookieStorePath != "" {
				if err := solverCache.SaveToDir(cfg.CookieStorePath); err != nil {
					slog.Warn("solver: disk sync failed", "err", err)
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

	stats := proxy.NewStatsTracker()

	transport, err = proxy.NewTransport(proxy.TransportOptions{
		Dialer:         rot.Dialer(),
		TimeoutSeconds: cfg.TimeoutSecs,
		Profile:        cfg.Profile,
		Rotator:        rot,
		SolverCache:    solverCache,
		ExitIPProvider: func() string { return rot.Stats().CurrentIP },
		Stats:          stats,
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
		adminSrv = startAdmin(cfg.AdminListen, cfg.AdminToken, rot, solverCache, stats)
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
	// Persist solver cookies on clean shutdown.
	if solverCache != nil && cfg.CookieStorePath != "" {
		if err := solverCache.SaveToDir(cfg.CookieStorePath); err != nil {
			slog.Warn("solver: cookie store save on shutdown failed", "err", err)
		} else {
			slog.Info("solver: cookie store saved", "dir", cfg.CookieStorePath, "entries", solverCache.Size())
		}
	}
	return nil
}

// Admin endpoint path prefix. Leading-dot segments are illegal in
// DNS hostnames and URL authority components, so no real upstream
// target will ever have a path starting with /.internal/. This
// gives admin endpoints a collision-free namespace even if an
// operator mounts the admin mux on the same listener as the proxy
// (not the default, but possible).
const adminPrefix = "/.internal/"

func startAdmin(addr, token string, rot *rotator.Rotator, solverCache *solver.Cache, stats *proxy.StatsTracker) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc(adminPrefix+"healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rot.Stats())
	})
	// /.internal/solver exposes the per-host solver circuit-breaker
	// state. Open circuits indicate hosts where repeated
	// solve-then-retry still got challenged — likely WAF cookie
	// pinning. Useful for debugging "why is my request failing"
	// without reading server logs.
	mux.HandleFunc(adminPrefix+"solver", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if solverCache == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"enabled": false})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":      true,
			"cached_hosts": solverCache.Size(),
			"circuits":     solverCache.CircuitStatus(),
		})
	})
	// Per-host failure diagnostics. GET returns summary of all hosts
	// sorted by failure rate. DELETE /.internal/stats/{host} resets
	// a host's counters (manual override after fixing the cause).
	mux.HandleFunc(adminPrefix+"stats/", func(w http.ResponseWriter, r *http.Request) {
		host := strings.TrimPrefix(r.URL.Path, adminPrefix+"stats/")
		if host == "" {
			// GET /.internal/stats/ → summary of all hosts
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hosts": stats.Summary(),
			})
			return
		}
		if r.Method == http.MethodDelete {
			stats.ResetHost(host)
			if solverCache != nil {
				solverCache.ResetCircuitsForHost(host) // reset circuit breaker for all IPs
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// GET /.internal/stats/{host} → detailed per-IP breakdown
		detail := stats.HostDetail(host)
		if detail == nil {
			http.Error(w, "no stats for host", http.StatusNotFound)
			return
		}
		diag, rec := stats.Diagnose(host)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"host":           detail,
			"diagnosis":      diag,
			"recommendation": rec,
		})
	})
	mux.HandleFunc(adminPrefix+"stats", func(w http.ResponseWriter, r *http.Request) {
		// Redirect /.internal/stats → /.internal/stats/
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"hosts": stats.Summary(),
		})
	})
	mux.HandleFunc(adminPrefix+"rotate", func(w http.ResponseWriter, r *http.Request) {
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
