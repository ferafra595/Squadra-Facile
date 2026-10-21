# SquadraFacile — versione semplificata (2 cartelle)

Questa è la **base pubblicabile** di SquadraFacile, non ancora il gestionale completo.

## Struttura

- `public/` — sito web e manifest.
- `functions/` — API Cloudflare Pages (`GET /api`).
- `schema.sql` — database D1, nella radice.
- `wrangler.toml` — configurazione Cloudflare.
- `package.json` — comandi opzionali.

## Pubblicazione GitHub + Cloudflare Pages

1. Estrai lo ZIP e carica **il contenuto**, non la cartella esterna, nella radice del repository GitHub `SquadraFacile`.
2. In Cloudflare crea il database D1 `squadrafacile-db`.
3. Sostituisci `INSERISCI_DATABASE_ID` in `wrangler.toml` con l'ID reale del database.
4. In Cloudflare Pages, collega il repository GitHub e imposta: **Framework None**, **Build command vuoto**, **Build output directory `public`**, **Root `/`**.
5. In Pages > Settings > Bindings collega D1 con il nome **DB** al database creato (per Production e, se serve, Preview), poi ridistribuisci.
6. In D1 > Console incolla ed esegui `schema.sql` oppure usa `npx wrangler d1 execute squadrafacile-db --remote --file=./schema.sql` dopo aver effettuato il login a Cloudflare.
7. Visita `https://TUO-SITO.pages.dev/api`: con binding configurato dovrebbe restituire `{"status":"ok","database":"connected"}`.

**Nota:** la pagina iniziale è una landing. Non sono ancora attivi login, gestione rosa, convocazioni, importazione calendari o Stripe. Lo schema dati è preparatorio: prima di creare API di scrittura servono autenticazione e controlli dei permessi.
