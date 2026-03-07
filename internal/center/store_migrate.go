package center

import (
	"fmt"
	"os"
	"strings"
)

type StoreMigrationResult struct {
	Devices  int
	Policies int
	Releases int
}

func MigrateFileStoreToSQLite(filePath, sqlitePath string, overwrite bool) (StoreMigrationResult, error) {
	filePath = strings.TrimSpace(filePath)
	sqlitePath = strings.TrimSpace(sqlitePath)
	if filePath == "" {
		return StoreMigrationResult{}, fmt.Errorf("file path is required")
	}
	if sqlitePath == "" {
		return StoreMigrationResult{}, fmt.Errorf("sqlite path is required")
	}
	if err := requireSourceExists(filePath, "file store"); err != nil {
		return StoreMigrationResult{}, err
	}
	if err := ensureDestinationWritable(sqlitePath, overwrite, "sqlite destination"); err != nil {
		return StoreMigrationResult{}, err
	}

	src, err := loadDeviceStore(StorageConfig{
		Backend:    storageBackendFile,
		Path:       filePath,
		SQLitePath: sqlitePath,
	})
	if err != nil {
		return StoreMigrationResult{}, fmt.Errorf("load file store: %w", err)
	}
	dst, err := loadDeviceStore(StorageConfig{
		Backend:    storageBackendSQLite,
		Path:       filePath,
		SQLitePath: sqlitePath,
	})
	if err != nil {
		return StoreMigrationResult{}, fmt.Errorf("load sqlite store: %w", err)
	}
	defer closeStoreDB(dst)

	result, err := copyStoreState(dst, src)
	if err != nil {
		return StoreMigrationResult{}, err
	}
	return result, nil
}

func MigrateSQLiteStoreToFile(sqlitePath, filePath string, overwrite bool) (StoreMigrationResult, error) {
	filePath = strings.TrimSpace(filePath)
	sqlitePath = strings.TrimSpace(sqlitePath)
	if filePath == "" {
		return StoreMigrationResult{}, fmt.Errorf("file path is required")
	}
	if sqlitePath == "" {
		return StoreMigrationResult{}, fmt.Errorf("sqlite path is required")
	}
	if err := requireSourceExists(sqlitePath, "sqlite store"); err != nil {
		return StoreMigrationResult{}, err
	}
	if err := ensureDestinationWritable(filePath, overwrite, "file destination"); err != nil {
		return StoreMigrationResult{}, err
	}

	src, err := loadDeviceStore(StorageConfig{
		Backend:    storageBackendSQLite,
		Path:       filePath,
		SQLitePath: sqlitePath,
	})
	if err != nil {
		return StoreMigrationResult{}, fmt.Errorf("load sqlite store: %w", err)
	}
	defer closeStoreDB(src)

	dst, err := loadDeviceStore(StorageConfig{
		Backend:    storageBackendFile,
		Path:       filePath,
		SQLitePath: sqlitePath,
	})
	if err != nil {
		return StoreMigrationResult{}, fmt.Errorf("load file store: %w", err)
	}

	result, err := copyStoreState(dst, src)
	if err != nil {
		return StoreMigrationResult{}, err
	}
	return result, nil
}

func copyStoreState(dst, src *deviceStore) (StoreMigrationResult, error) {
	devices := src.list()
	policies := src.listPolicies()
	releases := src.listReleases()

	nextDevices := make(map[string]DeviceRecord, len(devices))
	for _, rec := range devices {
		next := rec
		if len(rec.RevokedKeys) > 0 {
			next.RevokedKeys = append([]RevokedKeyRecord(nil), rec.RevokedKeys...)
		}
		nextDevices[next.DeviceID] = next
	}
	nextPolicies := make(map[string]PolicyRecord, len(policies))
	for _, rec := range policies {
		nextPolicies[rec.Version] = rec
	}
	nextReleases := make(map[string]ReleaseRecord, len(releases))
	for _, rec := range releases {
		nextReleases[rec.Version] = rec
	}

	dst.mu.Lock()
	defer dst.mu.Unlock()
	dst.devices = nextDevices
	dst.policies = nextPolicies
	dst.releases = nextReleases
	if err := dst.saveLocked(); err != nil {
		return StoreMigrationResult{}, fmt.Errorf("persist migrated store: %w", err)
	}
	return StoreMigrationResult{
		Devices:  len(nextDevices),
		Policies: len(nextPolicies),
		Releases: len(nextReleases),
	}, nil
}

func requireSourceExists(path, kind string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s not found: %s", kind, path)
		}
		return fmt.Errorf("stat %s: %w", kind, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s path is a directory: %s", kind, path)
	}
	return nil
}

func ensureDestinationWritable(path string, overwrite bool, kind string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", kind, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s path is a directory: %s", kind, path)
	}
	if !overwrite && info.Size() > 0 {
		return fmt.Errorf("%s already exists: %s (use overwrite)", kind, path)
	}
	return nil
}

func closeStoreDB(s *deviceStore) {
	if s == nil || s.db == nil {
		return
	}
	_ = s.db.Close()
}
