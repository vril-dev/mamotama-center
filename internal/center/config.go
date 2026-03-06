package center

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	Server    ServerConfig    `json:"server"`
	Auth      AuthConfig      `json:"auth"`
	Storage   StorageConfig   `json:"storage"`
	Heartbeat HeartbeatConfig `json:"heartbeat"`
}

type ServerConfig struct {
	ListenAddress     string   `json:"listen_address"`
	ReadHeaderTimeout Duration `json:"read_header_timeout"`
	ReadTimeout       Duration `json:"read_timeout"`
	WriteTimeout      Duration `json:"write_timeout"`
	IdleTimeout       Duration `json:"idle_timeout"`
	ShutdownTimeout   Duration `json:"shutdown_timeout"`
}

type AuthConfig struct {
	EnrollmentLicenseKeys []string `json:"enrollment_license_keys"`
	RequireTLS            bool     `json:"require_tls"`
	TrustForwardedProto   bool     `json:"trust_forwarded_proto"`
	NonceTTL              Duration `json:"nonce_ttl"`
	MaxNoncesPerDevice    int      `json:"max_nonces_per_device"`
}

type StorageConfig struct {
	Path string `json:"path"`
}

type HeartbeatConfig struct {
	MaxClockSkew               Duration `json:"max_clock_skew"`
	ExpectedInterval           Duration `json:"expected_interval"`
	MissedHeartbeatsForOffline int      `json:"missed_heartbeats_for_offline"`
	StaleAfter                 Duration `json:"stale_after"`
}

func defaultConfig() Config {
	return Config{
		Server: ServerConfig{
			ListenAddress:     ":18081",
			ReadHeaderTimeout: Duration{Duration: 3 * time.Second},
			ReadTimeout:       Duration{Duration: 10 * time.Second},
			WriteTimeout:      Duration{Duration: 15 * time.Second},
			IdleTimeout:       Duration{Duration: 60 * time.Second},
			ShutdownTimeout:   Duration{Duration: 10 * time.Second},
		},
		Auth: AuthConfig{
			EnrollmentLicenseKeys: nil,
			RequireTLS:            true,
			TrustForwardedProto:   false,
			NonceTTL:              Duration{Duration: 10 * time.Minute},
			MaxNoncesPerDevice:    256,
		},
		Storage: StorageConfig{
			Path: "./center-data/devices.json",
		},
		Heartbeat: HeartbeatConfig{
			MaxClockSkew:               Duration{Duration: 5 * time.Minute},
			ExpectedInterval:           Duration{Duration: 1 * time.Minute},
			MissedHeartbeatsForOffline: 3,
			StaleAfter:                 Duration{Duration: 30 * 24 * time.Hour},
		},
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := defaultConfig()

	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	normalize(&cfg)
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func normalize(cfg *Config) {
	cfg.Server.ListenAddress = strings.TrimSpace(cfg.Server.ListenAddress)
	cfg.Storage.Path = strings.TrimSpace(cfg.Storage.Path)
	for i, key := range cfg.Auth.EnrollmentLicenseKeys {
		cfg.Auth.EnrollmentLicenseKeys[i] = strings.TrimSpace(key)
	}
}

func validate(cfg Config) error {
	if cfg.Server.ListenAddress == "" {
		return fmt.Errorf("server.listen_address is required")
	}
	if cfg.Storage.Path == "" {
		return fmt.Errorf("storage.path is required")
	}
	if len(cfg.Auth.EnrollmentLicenseKeys) == 0 {
		return fmt.Errorf("auth.enrollment_license_keys requires at least one key")
	}
	for _, key := range cfg.Auth.EnrollmentLicenseKeys {
		if key == "" {
			return fmt.Errorf("auth.enrollment_license_keys contains empty key")
		}
		if len(key) < 16 {
			return fmt.Errorf("auth.enrollment_license_keys contains a key shorter than 16 chars")
		}
	}
	if cfg.Auth.NonceTTL.Duration <= 0 {
		return fmt.Errorf("auth.nonce_ttl must be positive")
	}
	if cfg.Auth.MaxNoncesPerDevice <= 0 {
		return fmt.Errorf("auth.max_nonces_per_device must be positive")
	}
	if cfg.Heartbeat.MaxClockSkew.Duration <= 0 {
		return fmt.Errorf("heartbeat.max_clock_skew must be positive")
	}
	if cfg.Heartbeat.ExpectedInterval.Duration <= 0 {
		return fmt.Errorf("heartbeat.expected_interval must be positive")
	}
	if cfg.Heartbeat.MissedHeartbeatsForOffline < 2 {
		return fmt.Errorf("heartbeat.missed_heartbeats_for_offline must be >= 2")
	}
	if cfg.Heartbeat.StaleAfter.Duration <= cfg.Heartbeat.ExpectedInterval.Duration {
		return fmt.Errorf("heartbeat.stale_after must be greater than heartbeat.expected_interval")
	}
	return nil
}
