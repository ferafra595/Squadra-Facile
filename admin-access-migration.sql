-- Eseguire una sola volta sulla console D1 di produzione. Non cancella dati.
CREATE TABLE IF NOT EXISTS sf_admin_sessions (id_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sf_disabled_teams (team_id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS admin_audit (id TEXT PRIMARY KEY, actor_email TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
