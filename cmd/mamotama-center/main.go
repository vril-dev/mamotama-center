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
	flag.StringVar(&configPath, "config", "center.config.json", "Path to center configuration file")
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.BoolVar(&validateConfigOnly, "validate-config", false, "Validate configuration file and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(versionText())
		return
	}

	cfg, err := center.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
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
