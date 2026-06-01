CREATE TABLE IF NOT EXISTS um_users (
	user_id   TEXT PRIMARY KEY,
	name      TEXT NOT NULL DEFAULT '',
	domain    TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS um_enrollments (
	code        TEXT PRIMARY KEY,
	user_id     TEXT NOT NULL,
	expire_at   TIMESTAMPTZ NOT NULL,
	used        BOOLEAN NOT NULL DEFAULT false,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS um_devices (
	pub_key_hex  TEXT PRIMARY KEY,
	user_id      TEXT NOT NULL,
	device_id    TEXT NOT NULL,
	display_name TEXT NOT NULL DEFAULT '',
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS um_policies (
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
);

CREATE TABLE IF NOT EXISTS um_certified_devices (
	group_name     TEXT NOT NULL DEFAULT '',
	device_id      TEXT NOT NULL,
	user_id        TEXT NOT NULL,
	display_name   TEXT NOT NULL DEFAULT '',
	pub_key_hex    TEXT NOT NULL,
	authed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
	auth_expire_at TIMESTAMPTZ NOT NULL,
	PRIMARY KEY (group_name, device_id)
);

CREATE TABLE IF NOT EXISTS um_device_tickets (
	ticket      TEXT PRIMARY KEY,
	user_id     TEXT NOT NULL,
	group_name  TEXT NOT NULL DEFAULT '',
	expire_at   TIMESTAMPTZ NOT NULL,
	used        BOOLEAN NOT NULL DEFAULT false,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS um_sequences (
	seq_name TEXT PRIMARY KEY,
	seq_val  BIGINT NOT NULL DEFAULT 0
);

INSERT INTO um_sequences (seq_name, seq_val)
VALUES ('user_seq', 0), ('enrollment_seq', 0)
ON CONFLICT (seq_name) DO NOTHING;
