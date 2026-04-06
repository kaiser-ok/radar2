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

	// Handlers
	systemH := handler.NewSystemHandler(cfg)
	switchH := handler.NewSwitchHandler(switchRepo)

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

		// TODO Phase 2: Port operations
		// r.Get("/switches/{swId}/ports", ...)
		// r.Get("/switches/{swId}/ports/{port}", ...)
		// r.Put("/switches/{swId}/ports/{port}/admin", ...)
		// r.Put("/switches/{swId}/ports/{port}/speed", ...)
		// r.Get("/switches/{swId}/ports/descriptions", ...)

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
