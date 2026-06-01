package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db *sql.DB
}

func Open(databaseURL string) (*Store, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &Store{db: db}, nil
}

func NewWithDB(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) EnsureSchema() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS um_users (
			user_id   TEXT PRIMARY KEY,
			name      TEXT NOT NULL DEFAULT '',
			domain    TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS um_enrollments (
			code        TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL,
			expire_at   TIMESTAMPTZ NOT NULL,
			used        BOOLEAN NOT NULL DEFAULT false,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS um_devices (
			pub_key_hex TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL,
			device_id   TEXT NOT NULL,
			display_name TEXT NOT NULL DEFAULT '',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS um_policies (
			user_id                    TEXT PRIMARY KEY,
			group_name                 TEXT NOT NULL DEFAULT '',
			user_expire_at_unix_ms     BIGINT NOT NULL DEFAULT 0,
			user_grace_period_seconds  BIGINT NOT NULL DEFAULT 0,
			allow_p2p                  BOOLEAN NOT NULL DEFAULT true,
			allow_relay                BOOLEAN NOT NULL DEFAULT true,
			max_devices                INTEGER NOT NULL DEFAULT 0,
			enrollment_ttl_seconds     BIGINT NOT NULL DEFAULT 0,
			gateway_ticket_ttl_seconds BIGINT NOT NULL DEFAULT 0,
			created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS um_certified_devices (
			group_name    TEXT NOT NULL DEFAULT '',
			device_id     TEXT NOT NULL,
			user_id       TEXT NOT NULL,
			display_name  TEXT NOT NULL DEFAULT '',
			pub_key_hex   TEXT NOT NULL,
			authed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
			auth_expire_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (group_name, device_id)
		)`,
		`CREATE TABLE IF NOT EXISTS um_device_tickets (
			ticket      TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL,
			group_name  TEXT NOT NULL DEFAULT '',
			expire_at   TIMESTAMPTZ NOT NULL,
			used        BOOLEAN NOT NULL DEFAULT false,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS um_sequences (
			seq_name TEXT PRIMARY KEY,
			seq_val  BIGINT NOT NULL DEFAULT 0
		)`,
		`INSERT INTO um_sequences (seq_name, seq_val)
		 VALUES ('user_seq', 0), ('enrollment_seq', 0)
		 ON CONFLICT (seq_name) DO NOTHING`,
		`DO $$
		DECLARE
			current_pk TEXT[];
		BEGIN
			SELECT ARRAY_AGG(att.attname ORDER BY att.attnum)
			  INTO current_pk
			  FROM pg_constraint con
			  JOIN pg_class rel ON rel.oid = con.conrelid
			  JOIN unnest(con.conkey) WITH ORDINALITY AS cols(attnum, ord) ON TRUE
			  JOIN pg_attribute att ON att.attrelid = rel.oid AND att.attnum = cols.attnum
			 WHERE rel.relname = 'um_certified_devices'
			   AND con.contype = 'p';
			IF current_pk = ARRAY['device_id'] THEN
				ALTER TABLE um_certified_devices DROP CONSTRAINT IF EXISTS um_certified_devices_pkey;
				ALTER TABLE um_certified_devices ADD CONSTRAINT um_certified_devices_pkey PRIMARY KEY (group_name, device_id);
			END IF;
		END
		$$`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure schema: %w\n%s", err, stmt)
		}
	}
	return nil
}
