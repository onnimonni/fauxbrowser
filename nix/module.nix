# NixOS module for fauxbrowser.
#
# Exposed as `nixosModules.default` from the flake. Typical usage:
#
#   {
#     inputs.fauxbrowser.url = "github:onnimonni/fauxbrowser";
#     outputs = { self, nixpkgs, fauxbrowser, ... }: {
#       nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
#         modules = [
#           fauxbrowser.nixosModules.default
#           {
#             services.fauxbrowser = {
#               enable = true;
#               wgConfFile = "/run/secrets/proton-vpn.conf";  # from sops/agenix
#               vpnCountries = [ "NL" "DE" ];
#               authTokenFile = "/run/secrets/fauxbrowser-auth";  # optional
#             };
#           }
#         ];
#       };
#     };
#   }
{ config, lib, pkgs, ... }:

let
  cfg = config.services.fauxbrowser;
  # Built binary is supplied by the flake's overlay below. When imported
  # as a module, the flake sets nixpkgs.overlays so `pkgs.fauxbrowser`
  # resolves to the Go build output for the host system.
  pkg = cfg.package;

  # EnvironmentFile written at activation time carrying only the non-
  # secret configuration. Secrets (auth tokens) live in a separate
  # file so they can be sops/agenix-managed.
  envFile = pkgs.writeText "fauxbrowser.env" (
    lib.concatStringsSep "\n" (
      lib.optional (cfg.listen != null) "FAUXBROWSER_LISTEN=${cfg.listen}"
      ++ lib.optional (cfg.adminListen != null) "FAUXBROWSER_ADMIN_LISTEN=${cfg.adminListen}"
      ++ lib.optional (cfg.profile != null) "FAUXBROWSER_PROFILE=${cfg.profile}"
      ++ lib.optional (cfg.vpnTier != null) "FAUXBROWSER_VPN_TIER=${cfg.vpnTier}"
      ++ lib.optional (cfg.vpnCountries != []) "FAUXBROWSER_VPN_COUNTRIES=${lib.concatStringsSep "," cfg.vpnCountries}"
      ++ lib.optional (cfg.vpnContinents != []) "FAUXBROWSER_VPN_CONTINENTS=${lib.concatStringsSep "," cfg.vpnContinents}"
      ++ lib.optional (cfg.logLevel != null) "FAUXBROWSER_LOG_LEVEL=${cfg.logLevel}"
      ++ lib.optional (cfg.wgConfFile != null) "FAUXBROWSER_WG_CONF=${cfg.wgConfFile}"
      ++ lib.optional (cfg.solver != "none") "FAUXBROWSER_SOLVER=${cfg.solver}"
      ++ lib.optional (cfg.solver != "none") "FAUXBROWSER_SOLVER_TTL=${cfg.solverTtl}"
      ++ lib.optional (cfg.solver != "none") "FAUXBROWSER_SOLVER_TIMEOUT=${cfg.solverTimeout}"
      ++ lib.optional (cfg.solver == "chromedp") "FAUXBROWSER_CHROMIUM_PATH=${cfg.chromiumPackage}/bin/chromium"
      ++ lib.optional (cfg.solver != "none" && cfg.cookieStorePath != null) "FAUXBROWSER_COOKIE_STORE=${cfg.cookieStorePath}"
      ++ [ "" ]  # trailing newline
    )
  );
in
{
  options.services.fauxbrowser = {
    enable = lib.mkEnableOption "fauxbrowser ProtonVPN + TLS-fingerprint-forging HTTP proxy";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.fauxbrowser;
      defaultText = lib.literalExpression "pkgs.fauxbrowser";
      description = "fauxbrowser package. Usually set by the flake overlay; override if you want a pinned version.";
    };

    listen = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "127.0.0.1:18443";
      description = ''
        Plaintext HTTP/1.1 + h2c listen address for the proxy.
        Non-loopback addresses REQUIRE `authTokenFile` to be set —
        fauxbrowser refuses to start otherwise.
      '';
    };

    adminListen = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "127.0.0.1:18444";
      description = ''
        Optional admin listener serving GET /.internal/healthz,
        GET /.internal/solver, and POST /.internal/rotate. Non-loopback
        addresses REQUIRE `adminTokenFile` to be set.
      '';
    };

    wgConfFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to a WireGuard .conf (wg-quick format) holding a ProtonVPN
        client private key + interface address + DNS. The [Peer] section
        is ignored — peers come from the embedded catalog.

        Use sops-nix or agenix to deliver this file out-of-band; DO NOT
        commit it to the Nix store.
      '';
      example = "/run/secrets/proton-vpn.conf";
    };

    vpnTier = lib.mkOption {
      type = lib.types.nullOr (lib.types.enum [ "free" "paid" "plus" "all" ]);
      default = "free";
      description = ''
        Proton server tier filter. Default `free`. Set to `paid`/`plus`
        only if your account is Plus AND your wg-conf key is registered
        on paid peers (the rotator will taint every paid peer otherwise
        via its post-handshake liveness probe).
      '';
    };

    vpnCountries = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      example = [ "NL" "DE" "CH" ];
      description = "ISO-3166-1 alpha-2 country allow-list. Empty = no restriction.";
    };

    vpnContinents = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      example = [ "EU" ];
      description = "Continent allow-list (EU, NA, AS, OC, SA, AF). Empty = no restriction.";
    };

    profile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "chrome146";
      description = "Browser profile (chrome146 / chrome144 / chrome133 / chrome131 / latest).";
    };

    solver = lib.mkOption {
      type = lib.types.enum [ "none" "chromedp" ];
      default = "chromedp";
      description = ''
        WAF challenge solver. `chromedp` (default) enables on-demand
        headless Chromium spawning to solve Cloudflare/Akamai/DataDome/
        PerimeterX JavaScript challenges; resulting clearance cookies
        are cached per (host, exit_ip) and reused on subsequent
        requests. Cookies survive VPN IP rotations and can optionally
        be persisted to disk via `cookieStorePath`.

        Setting this to `chromedp` automatically adds `pkgs.chromium`
        to the systemd unit's PATH and tweaks the sandbox to allow
        Chromium to spawn its sandbox helpers (Chromium needs to
        fork and create user namespaces).

        Set to `none` to disable the solver entirely — fauxbrowser
        stays a single self-contained binary with no Chromium
        dependency. Useful for targets that don't use WAF challenges.
      '';
    };

    chromiumPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.chromium;
      defaultText = lib.literalExpression "pkgs.chromium";
      description = ''
        Chromium package used by the chromedp solver. Override if
        you want to pin a specific Chromium build (e.g.
        `pkgs.ungoogled-chromium` for fingerprint hardening, or
        `pkgs.google-chrome` if you accept the proprietary build).
        Ignored when `solver = "none"`.
      '';
    };

    solverTtl = lib.mkOption {
      type = lib.types.str;
      default = "25m";
      description = ''
        How long to cache a (host, exit_ip) cookie bundle before
        re-running the solver. Cookies survive VPN IP rotations
        and are only flushed on CF-specific 403 or TTL expiry.
      '';
    };

    solverTimeout = lib.mkOption {
      type = lib.types.str;
      default = "30s";
      description = ''
        Max time per Chromium solve (startup + navigation +
        challenge wait + cookie extraction).
      '';
    };

    cookieStorePath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "/var/lib/fauxbrowser/cookies";
      description = ''
        Directory for persisting the solver's CF cookie cache to disk.
        Hostname-partitioned layout:

            /var/lib/fauxbrowser/cookies/www.shop.example.com/185.132.178.104.json

        One file per (host, exitIP) — O(1) per-entry writes, crash-safe,
        inspectable via `ls` / `cat`. Expired files are cleaned on startup.

        Cookies auto-persist on every solve and are restored on startup.
        Solved CF sessions survive process restarts without re-solving.

        Set to `null` to disable disk persistence (in-memory only).
        Ignored when `solver = "none"`.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.nullOr (lib.types.enum [ "debug" "info" "warn" "error" ]);
      default = "info";
      description = "slog level.";
    };

    authTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/fauxbrowser-auth";
      description = ''
        Path to a file containing the bearer token required on the
        proxy listener. MANDATORY when `listen` is non-loopback. The
        file should contain exactly one line with the token value.
      '';
    };

    adminTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/fauxbrowser-admin";
      description = ''
        Path to a file containing the bearer token required on the
        admin listener. MANDATORY when `adminListen` is non-loopback.
      '';
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      example = [ "-host-debounce" "10m" ];
      description = "Additional CLI arguments passed verbatim to the fauxbrowser binary.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the TCP port of `listen` in the firewall. Off by default.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.fauxbrowser = {
      description = "fauxbrowser — ProtonVPN + TLS fingerprint forging HTTP proxy";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      # Non-secret env vars go into a Nix-store file. Secrets
      # (auth tokens) are loaded from the user-provided paths via
      # systemd's LoadCredential machinery, which puts them under
      # $CREDENTIALS_DIRECTORY/<id>. A small ExecStartPre then writes
      # the values into a runtime-only env file read by the service.
      script = ''
        set -eu

        RUNTIME_ENV="''${RUNTIME_DIRECTORY}/env"
        : > "$RUNTIME_ENV"
        cat "${envFile}" >> "$RUNTIME_ENV"

        if [ -n "''${CREDENTIALS_DIRECTORY:-}" ]; then
          if [ -f "$CREDENTIALS_DIRECTORY/auth-token" ]; then
            printf 'FAUXBROWSER_AUTH_TOKEN=%s\n' "$(cat "$CREDENTIALS_DIRECTORY/auth-token")" >> "$RUNTIME_ENV"
          fi
          if [ -f "$CREDENTIALS_DIRECTORY/admin-token" ]; then
            printf 'FAUXBROWSER_ADMIN_TOKEN=%s\n' "$(cat "$CREDENTIALS_DIRECTORY/admin-token")" >> "$RUNTIME_ENV"
          fi
        fi

        exec ${lib.getExe pkg} ${lib.escapeShellArgs cfg.extraArgs}
      '';

      serviceConfig = {
        # Secrets loaded out-of-band; referenced by the ExecStartPre
        # script above via $CREDENTIALS_DIRECTORY.
        LoadCredential =
          lib.optional (cfg.authTokenFile != null) "auth-token:${toString cfg.authTokenFile}"
          ++ lib.optional (cfg.adminTokenFile != null) "admin-token:${toString cfg.adminTokenFile}";

        # Non-secret env (listen, wg-conf path, vpn filters).
        EnvironmentFile = envFile;

        # Runtime directory for the merged env file the script writes.
        RuntimeDirectory = "fauxbrowser";
        RuntimeDirectoryMode = "0750";

        # State directory for cookie persistence (/var/lib/fauxbrowser).
        # Survives service restarts; cleared only on explicit deletion.
        StateDirectory = "fauxbrowser";
        StateDirectoryMode = "0750";

        # DynamicUser with no shell, no home. Userspace WireGuard
        # means we do NOT need CAP_NET_ADMIN.
        DynamicUser = true;
        User = "fauxbrowser";
        Group = "fauxbrowser";

        # Hardened sandbox. See systemd.exec(5).
        # When solver = chromedp, Chromium needs:
        #   - user namespaces (its renderer sandbox)
        #   - to fork/exec helper processes
        #   - AF_NETLINK for some platform integrations
        # so we relax RestrictNamespaces and MemoryDenyWriteExecute
        # in that mode, and add chromium to PATH so chromedp can
        # exec it.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectHostname = true;
        ProtectClock = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        RestrictNamespaces = if cfg.solver == "chromedp" then false else true;
        LockPersonality = true;
        MemoryDenyWriteExecute = if cfg.solver == "chromedp" then false else true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        RestrictAddressFamilies =
          if cfg.solver == "chromedp"
          then [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" ]
          else [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        UMask = "0077";

        # Restart on crash, but not so aggressively that we burn the
        # Proton pool in a tight loop.
        Restart = "on-failure";
        RestartSec = "5s";

        # Stop grace — give the reaper room to drain retired tunnels.
        TimeoutStopSec = "30s";
      };

      # When the chromedp solver is enabled, give the unit access
      # to the Chromium binary on PATH (chromedp invokes
      # exec.LookPath internally if no absolute path is set).
      path = lib.optional (cfg.solver == "chromedp") cfg.chromiumPackage;
    };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [
        (lib.toInt (lib.last (lib.splitString ":" cfg.listen)))
      ];
    };

    assertions = [
      {
        assertion = cfg.wgConfFile != null;
        message = "services.fauxbrowser.wgConfFile is required.";
      }
    ];
  };
}
