package center

import (
	"path/filepath"
	"testing"
)

func TestSQLiteStoreInitCheckMigrate(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "center-data", "center.db")

	if err := InitSQLiteStore(dbPath); err != nil {
		t.Fatalf("init sqlite: %v", err)
	}
	if err := CheckSQLiteStore(dbPath); err != nil {
		t.Fatalf("check sqlite after init: %v", err)
	}
	if err := MigrateSQLiteStore(dbPath); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	if err := CheckSQLiteStore(dbPath); err != nil {
		t.Fatalf("check sqlite after migrate: %v", err)
	}
}

func TestStorageConfigSQLiteDBPath(t *testing.T) {
	t.Parallel()
	cfg := StorageConfig{SQLitePath: "  ./center-data/center.db  "}
	if got, want := cfg.SQLiteDBPath(), "./center-data/center.db"; got != want {
		t.Fatalf("SQLiteDBPath()=%q want=%q", got, want)
	}
}
