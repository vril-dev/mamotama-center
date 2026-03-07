package center

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 1

var sqliteDDL = []string{
	`CREATE TABLE IF NOT EXISTS devices (
		device_id TEXT PRIMARY KEY,
		public_key_fingerprint_sha256 TEXT NOT NULL,
		key_id TEXT NOT NULL DEFAULT '',
		record_json TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_public_key_fingerprint_sha256
		ON devices(public_key_fingerprint_sha256);`,
	`CREATE TABLE IF NOT EXISTS policies (
		version TEXT PRIMARY KEY,
		status TEXT NOT NULL,
		record_json TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS releases (
		version TEXT PRIMARY KEY,
		status TEXT NOT NULL,
		record_json TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS audit_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		payload_json TEXT NOT NULL,
		created_at TEXT NOT NULL
	);`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_device_created_at
		ON audit_events(device_id, created_at DESC);`,
	`CREATE TABLE IF NOT EXISTS log_batches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id TEXT NOT NULL,
		message_at TEXT NOT NULL,
		nonce TEXT NOT NULL,
		entry_count INTEGER NOT NULL,
		content_sha256 TEXT NOT NULL,
		payload_gzip_ndjson BLOB NOT NULL,
		created_at TEXT NOT NULL
	);`,
	`CREATE INDEX IF NOT EXISTS idx_log_batches_device_created_at
		ON log_batches(device_id, created_at DESC);`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_log_batches_device_nonce
		ON log_batches(device_id, nonce);`,
}

var sqliteRequiredTables = []string{
	"devices",
	"policies",
	"releases",
	"audit_events",
	"log_batches",
}

var sqliteRequiredIndexes = []string{
	"idx_devices_public_key_fingerprint_sha256",
	"idx_audit_events_device_created_at",
	"idx_log_batches_device_created_at",
	"idx_log_batches_device_nonce",
}

func InitSQLiteStore(path string) error {
	db, err := openSQLite(path, true)
	if err != nil {
		return err
	}
	defer db.Close()
	return initSQLiteSchema(db)
}

func MigrateSQLiteStore(path string) error {
	return InitSQLiteStore(path)
}

func CheckSQLiteStore(path string) error {
	db, err := openSQLite(path, false)
	if err != nil {
		return err
	}
	defer db.Close()

	version, err := sqliteUserVersion(db)
	if err != nil {
		return err
	}
	if version != sqliteSchemaVersion {
		return fmt.Errorf("sqlite schema version mismatch: got=%d want=%d", version, sqliteSchemaVersion)
	}
	for _, table := range sqliteRequiredTables {
		ok, err := sqliteObjectExists(db, "table", table)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("missing sqlite table: %s", table)
		}
	}
	for _, idx := range sqliteRequiredIndexes {
		ok, err := sqliteObjectExists(db, "index", idx)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("missing sqlite index: %s", idx)
		}
	}
	return nil
}

func openSQLite(path string, createParent bool) (*sql.DB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}
	if createParent {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create sqlite dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := applySQLitePragmas(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func applySQLitePragmas(db *sql.DB) error {
	for _, stmt := range []string{
		`PRAGMA journal_mode = WAL;`,
		`PRAGMA synchronous = NORMAL;`,
		`PRAGMA foreign_keys = ON;`,
		`PRAGMA busy_timeout = 5000;`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("apply sqlite pragma %q: %w", stmt, err)
		}
	}
	return nil
}

func initSQLiteSchema(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin sqlite tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for _, stmt := range sqliteDDL {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("exec sqlite ddl: %w", err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, sqliteSchemaVersion)); err != nil {
		return fmt.Errorf("set sqlite user_version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite tx: %w", err)
	}
	return nil
}

func sqliteUserVersion(db *sql.DB) (int, error) {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("query sqlite user_version: %w", err)
	}
	return version, nil
}

func sqliteObjectExists(db *sql.DB, typ, name string) (bool, error) {
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(1) FROM sqlite_master WHERE type = ? AND name = ?`,
		typ, name,
	).Scan(&count); err != nil {
		return false, fmt.Errorf("query sqlite_master: %w", err)
	}
	return count > 0, nil
}
