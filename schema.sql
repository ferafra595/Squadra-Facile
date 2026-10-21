PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS teams (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, format INTEGER NOT NULL CHECK(format IN (5,7,11)), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS players (
 id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
 name TEXT NOT NULL, number INTEGER, role TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_players_team ON players(team_id);
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
 type TEXT NOT NULL CHECK(type IN ('training','match','other')),
 title TEXT NOT NULL, starts_at TEXT NOT NULL, venue TEXT, opponent TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_events_team_date ON events(team_id, starts_at);
CREATE TABLE IF NOT EXISTS availability (
 event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
 player_id TEXT NOT NULL REFERENCES players(id) ON DELETE CASCADE,
 status TEXT NOT NULL CHECK(status IN ('yes','no','maybe')),
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(event_id,player_id)
);
-- Prima di esporre API di scrittura aggiungere autenticazione, autorizzazione per squadra e token personali dei giocatori.
