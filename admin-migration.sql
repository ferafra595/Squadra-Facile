-- Eseguire UNA VOLTA nel database D1 REMOTO collegato a Pages.
CREATE TABLE IF NOT EXISTS admin_audit (
 id TEXT PRIMARY KEY,
 actor_email TEXT NOT NULL,
 action TEXT NOT NULL,
 target TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit(created_at);
