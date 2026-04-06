package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"new_radar/internal/auth"
	"new_radar/internal/config"
	"new_radar/internal/db"
	"new_radar/internal/handler"
	"new_radar/internal/mib"
	"new_radar/internal/onboarding"
	"new_radar/internal/service"
	"new_radar/internal/snmp"
)

var (
	version   = "2.0.0"
	buildDate = "dev"
)

func main() {
	configPath := flag.String("config", "configs/radar.yaml", "path to config file")
	flag.Parse()

	// Logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Config
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	cfg.Version = version
	cfg.BuildDate = buildDate

	// Database
	database, err := db.Open(cfg.Database.Path)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	if err := db.Migrate(database, "migrations/001_initial.sql"); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}
	slog.Info("database ready", "path", cfg.Database.Path)

	// Repos
	switchRepo := db.NewSwitchRepo(database)

	// SNMP
	snmpClient := snmp.NewClient(cfg.SNMP.Timeout, cfg.SNMP.Retries, cfg.SNMP.MaxOIDsPerReq)
	oidRegistry, err := snmp.LoadOIDs(cfg.SNMP.OIDFile)
	if err != nil {
		slog.Error("failed to load OID registry", "error", err)
		os.Exit(1)
	}
	slog.Info("OID registry loaded", "file", cfg.SNMP.OIDFile)

	// 4-layer device profile system (fingerprint → capability → vendor mapping → override)
	profiles, err := config.LoadProfiles("profiles")
	if err != nil {
		slog.Warn("failed to load device profiles", "error", err)
	} else {
		slog.Info("device profiles loaded")
	}

	// MIB store
	mibStore, err := mib.NewStore(database, "mibs")
	if err != nil {
		slog.Warn("failed to initialize MIB store", "error", err)
	} else {
		slog.Info("MIB store ready")
	}

	// Services
	portSvc := service.NewPortService(snmpClient, oidRegistry, profiles)

	// Handlers
	systemH := handler.NewSystemHandler(cfg)
	switchH := handler.NewSwitchHandler(switchRepo)
	portH := handler.NewPortHandler(portSvc, switchRepo)
	mibH := handler.NewMIBHandler(mibStore)

	// Onboarding service
	onboardingSvc, err := onboarding.NewService(database, "onboarding")
	if err != nil {
		slog.Warn("failed to initialize onboarding service", "error", err)
	} else {
		slog.Info("onboarding service ready")
	}
	onboardingH := handler.NewOnboardingHandler(onboardingSvc)

	// Router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(cfg.Server.WriteTimeout))
	r.Use(auth.BasicAuth(cfg.Auth.Username, cfg.Auth.Password))

	// v2 API routes
	r.Route("/api/v2", func(r chi.Router) {
		// System
		r.Get("/version", systemH.Version)
		r.Get("/interfaces", systemH.Interfaces)

		// Switches
		r.Get("/units/{unitId}/switches", switchH.ListByUnit)
		r.Post("/units/{unitId}/switches", switchH.Create)
		r.Get("/switches/{swId}", switchH.Get)
		r.Put("/switches/{swId}", switchH.Update)
		r.Delete("/switches/{swId}", switchH.Delete)

		// Port operations
		r.Get("/switches/{swId}/ports", portH.ListPorts)
		r.Get("/switches/{swId}/ports/descriptions", portH.GetDescriptions)
		r.Get("/switches/{swId}/ports/{port}", portH.GetPort)
		r.Put("/switches/{swId}/ports/{port}/admin", portH.SetPortAdmin)
		// TODO Phase 2b: r.Put("/switches/{swId}/ports/{port}/speed", ...)

		// TODO Phase 3: Network tools
		// r.Post("/tools/ping", ...)
		// r.Post("/tools/traceroute", ...)
		// r.Post("/tools/arping", ...)
		// r.Post("/tools/dad-check", ...)
		// r.Get("/tools/tasks/{taskId}", ...)

		// TODO Phase 4: PoE
		// r.Get("/switches/{swId}/poe", ...)
		// r.Get("/switches/{swId}/poe/report", ...)
		// r.Put("/switches/{swId}/poe/{port}", ...)

		// TODO Phase 4: Switch info
		// r.Get("/switches/{swId}/cpu", ...)
		// r.Get("/switches/{swId}/stats", ...)
		// r.Get("/switches/{swId}/vlans", ...)
		// r.Get("/switches/{swId}/fdb", ...)
		// r.Delete("/switches/{swId}/fdb", ...)
		// r.Post("/switches/{swId}/reboot", ...)

		// TODO Phase 5: SNMP
		// r.Post("/snmp/test", ...)
		// r.Post("/snmp/query", ...)
		// r.Post("/snmp/discovery", ...)

		// TODO Phase 5: Topology
		// r.Post("/units/{unitId}/topology/rebuild", ...)
		// r.Get("/units/{unitId}/ports", ...)

		// TODO Phase 6: MAC/IP
		// r.Get("/units/{unitId}/mac/{mac}/location", ...)
		// r.Post("/units/{unitId}/mac/refresh", ...)
		// r.Get("/units/{unitId}/ip/{ip}/resolve", ...)

		// TODO Phase 6: MAC isolation
		// r.Get("/units/{unitId}/isolation", ...)
		// r.Post("/units/{unitId}/isolation", ...)
		// r.Delete("/units/{unitId}/isolation/{mac}", ...)

		// MIB management
		r.Post("/mibs/upload", mibH.Upload)
		r.Get("/mibs/modules", mibH.ListModules)
		r.Get("/mibs/lookup", mibH.LookupByName)
		r.Get("/mibs/resolve", mibH.ResolveOID)
		r.Get("/mibs/search", mibH.Search)
		r.Delete("/mibs/modules", mibH.DeleteModule)

		// Onboarding workflow
		r.Post("/onboarding", onboardingH.CreateCase)
		r.Get("/onboarding", onboardingH.ListCases)
		r.Get("/onboarding/{id}", onboardingH.GetCase)
		r.Post("/onboarding/{id}/fingerprint", onboardingH.SubmitFingerprint)
		r.Post("/onboarding/{id}/evidence", onboardingH.UploadEvidence)
		r.Post("/onboarding/{id}/analyze", onboardingH.Analyze)
		r.Get("/onboarding/{id}/drafts", onboardingH.GetDrafts)
		r.Post("/onboarding/{id}/approve", onboardingH.Approve)

		// TODO Phase 7: RSPAN
		// r.Route("/rspan", func(r chi.Router) { ... })
	})

	// Server
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  120 * time.Second,
	}

	slog.Info("starting radar v2", "addr", addr, "version", version)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
