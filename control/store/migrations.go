package store

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

const migrationTableDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version   TEXT PRIMARY KEY,
	checksum  TEXT NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version  string
	fileName string
	checksum string
	sql      string
}

func (s *Store) ApplyMigrations() error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin schema migration tx: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(migrationTableDDL); err != nil {
		return fmt.Errorf("ensure schema_migrations table: %w", err)
	}
	applied, err := loadAppliedMigrations(tx)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if checksum, ok := applied[m.version]; ok {
			if checksum != m.checksum {
				return fmt.Errorf("schema migration checksum mismatch for %s", m.version)
			}
			continue
		}
		if _, err := tx.Exec(m.sql); err != nil {
			return fmt.Errorf("apply schema migration %s: %w", m.version, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, m.version, m.checksum); err != nil {
			return fmt.Errorf("record schema migration %s: %w", m.version, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migrations: %w", err)
	}
	return nil
}

func (s *Store) RequireMigration(version string) error {
	if strings.TrimSpace(version) == "" {
		return fmt.Errorf("required schema version is empty")
	}
	var tableName sql.NullString
	if err := s.db.QueryRow(`SELECT to_regclass('public.schema_migrations')`).Scan(&tableName); err != nil {
		return fmt.Errorf("check schema_migrations table: %w", err)
	}
	if !tableName.Valid || strings.TrimSpace(tableName.String) == "" {
		return fmt.Errorf("database schema is not initialized; run `sdl-control migrate`")
	}
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists); err != nil {
		return fmt.Errorf("check required schema migration %s: %w", version, err)
	}
	if !exists {
		return fmt.Errorf("database schema is missing required migration %s; run `sdl-control migrate`", version)
	}
	return nil
}

func LatestMigrationVersion(scope string) (string, error) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return "", fmt.Errorf("migration scope is empty")
	}
	migrations, err := loadMigrations()
	if err != nil {
		return "", err
	}
	scopeToken := "_" + scope + "_"
	for i := len(migrations) - 1; i >= 0; i-- {
		if strings.Contains(migrations[i].version, scopeToken) {
			return migrations[i].version, nil
		}
	}
	return "", fmt.Errorf("no schema migration found for scope %q", scope)
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	migrations := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || path.Ext(entry.Name()) != ".sql" {
			continue
		}
		version := strings.TrimSuffix(entry.Name(), ".sql")
		content, err := migrationFS.ReadFile(path.Join("migrations", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read embedded migration %s: %w", entry.Name(), err)
		}
		sum := sha256.Sum256(content)
		migrations = append(migrations, migration{
			version:  version,
			fileName: entry.Name(),
			checksum: hex.EncodeToString(sum[:]),
			sql:      string(content),
		})
	}
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].fileName < migrations[j].fileName
	})
	return migrations, nil
}

func loadAppliedMigrations(tx *sql.Tx) (map[string]string, error) {
	rows, err := tx.Query(`SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("load applied schema migrations: %w", err)
	}
	defer rows.Close()
	applied := map[string]string{}
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("scan applied schema migration: %w", err)
		}
		applied[version] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied schema migrations: %w", err)
	}
	return applied, nil
}
