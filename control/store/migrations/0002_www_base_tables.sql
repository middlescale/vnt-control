CREATE TABLE IF NOT EXISTS users (
	id           TEXT PRIMARY KEY,
	email        TEXT NOT NULL,
	display_name TEXT NOT NULL DEFAULT '',
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_identities (
	provider         TEXT NOT NULL,
	provider_subject TEXT NOT NULL,
	user_id          TEXT NOT NULL REFERENCES users(id),
	PRIMARY KEY (provider, provider_subject)
);

CREATE TABLE IF NOT EXISTS sdl_accounts (
	user_id          TEXT NOT NULL REFERENCES users(id),
	sdl_user_id      TEXT NOT NULL UNIQUE,
	group_name       TEXT NOT NULL,
	domain_name      TEXT NOT NULL DEFAULT 'ms.net',
	provision_status TEXT NOT NULL DEFAULT 'provisioned',
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (user_id)
);
