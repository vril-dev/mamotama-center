package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/vril/mamotama-center/internal/center"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func versionText() string {
	return fmt.Sprintf("mamotama-center version=%s commit=%s build_date=%s go=%s", version, commit, buildDate, runtime.Version())
}

func main() {
	var configPath string
	var showVersion bool
	var validateConfigOnly bool
	var dbInitOnly bool
	var dbCheckOnly bool
	var dbMigrateOnly bool
	var migrateFileToSQLite bool
	var migrateSQLiteToFile bool
	var migrateOverwrite bool
	flag.StringVar(&configPath, "config", "center.config.json", "Path to center configuration file")
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.BoolVar(&validateConfigOnly, "validate-config", false, "Validate configuration file and exit")
	flag.BoolVar(&dbInitOnly, "db-init", false, "Initialize SQLite schema and exit")
	flag.BoolVar(&dbCheckOnly, "db-check", false, "Check SQLite schema and exit")
	flag.BoolVar(&dbMigrateOnly, "db-migrate", false, "Migrate SQLite schema and exit")
	flag.BoolVar(&migrateFileToSQLite, "migrate-file-to-sqlite", false, "Migrate file store data into SQLite store and exit")
	flag.BoolVar(&migrateSQLiteToFile, "migrate-sqlite-to-file", false, "Migrate SQLite store data into file store and exit")
	flag.BoolVar(&migrateOverwrite, "migrate-overwrite", false, "Allow destination overwrite for migration commands")
	flag.Parse()

	if showVersion {
		fmt.Println(versionText())
		return
	}

	cfg, err := center.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if dbInitOnly || dbCheckOnly || dbMigrateOnly || migrateFileToSQLite || migrateSQLiteToFile {
		modeCount := 0
		if dbInitOnly {
			modeCount++
		}
		if dbCheckOnly {
			modeCount++
		}
		if dbMigrateOnly {
			modeCount++
		}
		if migrateFileToSQLite {
			modeCount++
		}
		if migrateSQLiteToFile {
			modeCount++
		}
		if modeCount > 1 {
			log.Fatalf("db/migration flags are mutually exclusive")
		}
		dbPath := cfg.Storage.SQLiteDBPath()
		switch {
		case dbInitOnly:
			if err := center.InitSQLiteStore(dbPath); err != nil {
				log.Fatalf("init sqlite store: %v", err)
			}
			fmt.Printf("sqlite initialized: %s\n", dbPath)
		case dbCheckOnly:
			if err := center.CheckSQLiteStore(dbPath); err != nil {
				log.Fatalf("check sqlite store: %v", err)
			}
			fmt.Printf("sqlite check ok: %s\n", dbPath)
		case dbMigrateOnly:
			if err := center.MigrateSQLiteStore(dbPath); err != nil {
				log.Fatalf("migrate sqlite store: %v", err)
			}
			fmt.Printf("sqlite migrated: %s\n", dbPath)
		case migrateFileToSQLite:
			result, err := center.MigrateFileStoreToSQLite(cfg.Storage.Path, dbPath, migrateOverwrite)
			if err != nil {
				log.Fatalf("migrate file->sqlite: %v", err)
			}
			fmt.Printf("file->sqlite migrated: file=%s sqlite=%s devices=%d policies=%d releases=%d\n",
				cfg.Storage.Path, dbPath, result.Devices, result.Policies, result.Releases)
		case migrateSQLiteToFile:
			result, err := center.MigrateSQLiteStoreToFile(dbPath, cfg.Storage.Path, migrateOverwrite)
			if err != nil {
				log.Fatalf("migrate sqlite->file: %v", err)
			}
			fmt.Printf("sqlite->file migrated: sqlite=%s file=%s devices=%d policies=%d releases=%d\n",
				dbPath, cfg.Storage.Path, result.Devices, result.Policies, result.Releases)
		}
		return
	}
	if validateConfigOnly {
		fmt.Printf("config is valid: %s\n", configPath)
		return
	}

	logger := log.New(os.Stdout, "", 0)
	centerServer, err := center.NewServer(cfg, logger)
	if err != nil {
		log.Fatalf("build center server: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.Server.ListenAddress,
		Handler:           centerServer.Handler(),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration,
		ReadTimeout:       cfg.Server.ReadTimeout.Duration,
		WriteTimeout:      cfg.Server.WriteTimeout.Duration,
		IdleTimeout:       cfg.Server.IdleTimeout.Duration,
	}

	go func() {
		logger.Printf(`{"level":"info","msg":"starting center server","listen_address":"%s"}`, cfg.Server.ListenAddress)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf(`{"level":"fatal","msg":"center server stopped unexpectedly","error":"%s"}`, err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Printf(`{"level":"error","msg":"center graceful shutdown failed","error":"%s"}`, err)
		_ = srv.Close()
	}

	time.Sleep(50 * time.Millisecond)
	logger.Printf(`{"level":"info","msg":"center server shutdown complete"}`)
}
