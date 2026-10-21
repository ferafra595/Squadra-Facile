# SquadraFacile 2.0 — Cloudflare Pages

**Due cartelle soltanto:** `public/` (interfaccia) e `functions/` (API Pages Functions). I file `schema.sql`, `wrangler.toml` e `package.json` sono nella radice.

## Installazione su Cloudflare

1. Carica il contenuto di questo ZIP **nella radice del repository GitHub esistente**, sostituendo i file precedenti. Elimina `functions/api.js` del vecchio starter: è sostituito da `functions/[[path]].js`.
2. Mantieni il progetto Cloudflare Pages esistente e la directory di output `public`. Framework preset: None; build command: vuoto.
3. In Cloudflare > D1 crea `squadrafacile-db` se non esiste già.
4. Nelle impostazioni di Pages > Bindings aggiungi **D1 database**, nome variabile `DB`, scegli il database. Impostalo sia per Production sia per Preview se usi le anteprime.
5. Cloudflare > D1 > database > Console: esegui il contenuto di `schema.sql` sul database **remoto**. Le istruzioni `CREATE TABLE IF NOT EXISTS` mantengono i dati già presenti nello starter.
6. Esegui un nuovo deploy di Pages, poi verifica `https://TUO-DOMINIO.pages.dev/api/status` che deve restituire `{ "ok": true }`.

Se usi Wrangler con GitHub, aggiorna `database_id` nel `wrangler.toml` con l'ID vero del tuo database; **non** lasciare `INSERISCI_DATABASE_ID` per deploy gestiti da Wrangler. Se configuri tutto dal dashboard Cloudflare, usa il binding `DB` lì.

## Funzionalità incluse

- Registrazione e accesso con password PBKDF2 e cookie di sessione HttpOnly.
- Creazione squadre calcio a 5, 7 e 11; dati separati per squadra.
- Gestione rosa (aggiunta/eliminazione) e calendario manuale (creazione/eliminazione).
- Link personali generati dal dirigente: la generazione di un nuovo link revoca quello precedente. Il dirigente deve condividerlo subito, perché il token non viene conservato in chiaro.
- Disponibilità del giocatore tramite link senza login.
- Convocazioni e condivisione via WhatsApp.
- Dati persistenti in D1; autorizzazione server-side per squadra.

## Non ancora inclusi

Importazione e sincronizzazione dei calendari LND, modifica dei giocatori, cassa, statistiche, Stripe, amministrazione centrale, recupero password e protezioni avanzate anti-abuso. **Non attivare ancora abbonamenti a pagamento.** Prima di un lancio pubblico aggiungere rate limiting su login/registrazione, reset password, log di sicurezza, privacy e termini, test approfonditi e procedure di backup.

## Nota sicurezza

Le API usano cookie `Secure`, quindi il login funziona su HTTPS (Cloudflare Pages). I link dei giocatori sono credenziali personali: se condivisi impropriamente, chi li possiede può rispondere a nome del giocatore. Per revocare un link basta generarne uno nuovo.
