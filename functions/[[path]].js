const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...headers}});
const err=(message,status=400)=>json({error:message},status);
const uid=()=>crypto.randomUUID();
const token=()=>{let b=new Uint8Array(32);crypto.getRandomValues(b);return Array.from(b,x=>x.toString(16).padStart(2,'0')).join('')};
const sha=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s))),x=>x.toString(16).padStart(2,'0')).join('');
const hex=a=>Array.from(a,x=>x.toString(16).padStart(2,'0')).join('');
async function hashPassword(pass,salt){let k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pass),'PBKDF2',false,['deriveBits']);return hex(new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:100000,hash:'SHA-256'},k,256)))}
const valid=(v,n=150)=>typeof v==='string'&&v.trim().length>0&&v.trim().length<=n;
const clean=(v,n=150)=>typeof v==='string'?v.trim().slice(0,n):'';
async function auth(db,request){let c=request.headers.get('cookie')||'';let t=c.match(/(?:^|;\s*)sf_session=([a-f0-9]{64})(?:;|$)/)?.[1];if(!t)return null;return db.prepare("SELECT users.id,users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.id_hash=? AND sessions.expires_at>datetime('now') AND NOT EXISTS (SELECT 1 FROM sf_disabled_users du WHERE du.user_id=users.id)").bind(await sha(t)).first()}
const adminCookie=(t,maxAge)=>`sf_admin=${t}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const cookie=(t,maxAge)=>`sf_session=${t}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
async function teamAuth(db,user,teamId){if(!user||!teamId)return null;let disabled=await db.prepare('SELECT 1 FROM sf_disabled_teams WHERE team_id=?').bind(teamId).first();if(disabled)return null;let banned=await db.prepare('SELECT 1 FROM sf_disabled_users WHERE user_id=?').bind(user.id).first();if(banned)return null;let sub=await db.prepare('SELECT status,ends_at FROM sf_subscriptions WHERE team_id=?').bind(teamId).first();if(sub&&(sub.status==='expired'||sub.status==='cancelled'||sub.status==='past_due'||(sub.ends_at&&sub.ends_at.slice(0,10)<new Date().toISOString().slice(0,10))))return null;return db.prepare('SELECT role FROM team_members WHERE team_id=? AND user_id=?').bind(teamId,user.id).first()}
async function readBody(req){let len=Number(req.headers.get('content-length')||0);if(len>16000)throw Error('Richiesta troppo grande');return req.json()}
export async function onRequest({request,env}){
 const url=new URL(request.url),p=url.pathname;
 if(!p.startsWith('/api/'))return env.ASSETS.fetch(request);
 if(!env.DB)return err('Database D1 non collegato: aggiungi il binding DB su Cloudflare Pages.',503);
 const db=env.DB;
 // Ensure ADMIN-only tables exist before checking sessions or accepting login.
 // This makes first-time setup safe without a manual D1 migration.
 {
  try{
   await db.batch([
    db.prepare('CREATE TABLE IF NOT EXISTS sf_admin_sessions (id_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS sf_disabled_teams (team_id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)'),
    db.prepare('CREATE TABLE IF NOT EXISTS admin_audit (id TEXT PRIMARY KEY, actor_email TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)'),
    db.prepare("CREATE TABLE IF NOT EXISTS sf_subscriptions (team_id TEXT PRIMARY KEY, plan TEXT NOT NULL DEFAULT 'trial', status TEXT NOT NULL DEFAULT 'trial', starts_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, ends_at TEXT, notes TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare('CREATE TABLE IF NOT EXISTS sf_disabled_users (user_id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')
   ]);
  }catch(e){console.error('ADMIN schema initialization failed',e);return err('Impossibile inizializzare le tabelle ADMIN. Controlla il collegamento DB.',503)}
 }
 // Moduli stagione: migrazione non distruttiva, idempotente.
 try {await db.batch([
 db.prepare('CREATE TABLE IF NOT EXISTS sf_event_links (event_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP)'),
 db.prepare('CREATE TABLE IF NOT EXISTS sf_tactics (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, title TEXT NOT NULL, formation TEXT NOT NULL, phase TEXT NOT NULL, positions TEXT NOT NULL, notes TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)'),
 db.prepare('CREATE TABLE IF NOT EXISTS sf_progress (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, player_id TEXT, recorded_at TEXT NOT NULL, category TEXT NOT NULL, score INTEGER NOT NULL, strengths TEXT NOT NULL, improvements TEXT NOT NULL, action_plan TEXT NOT NULL)'),
 db.prepare('CREATE TABLE IF NOT EXISTS sf_finances (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, player_id TEXT, kind TEXT NOT NULL, amount_cents INTEGER NOT NULL, title TEXT NOT NULL, occurred_at TEXT NOT NULL, notes TEXT NOT NULL)'),
 db.prepare('CREATE TABLE IF NOT EXISTS sf_fixtures (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, competition TEXT NOT NULL, round TEXT NOT NULL, opponent TEXT NOT NULL, starts_at TEXT NOT NULL, venue TEXT NOT NULL, home INTEGER NOT NULL, goals_for INTEGER, goals_against INTEGER, source TEXT NOT NULL)'),
 db.prepare('CREATE TABLE IF NOT EXISTS sf_availability_log (id TEXT PRIMARY KEY, event_id TEXT NOT NULL, player_id TEXT NOT NULL, status TEXT NOT NULL, changed_at TEXT DEFAULT CURRENT_TIMESTAMP)')
 ]);}catch(e){console.error('Season schema',e);return err('Inizializzazione moduli stagione non riuscita',503)}
 if(request.method==='GET'&&p==='/api/status'){try{await db.prepare('SELECT id FROM users LIMIT 1').first();return json({ok:true})}catch{return err('Schema non applicato. Esegui schema.sql nel database D1.',503)}}
 const adminToken=(request.headers.get('cookie')||'').match(/(?:^|;\s*)sf_admin=([a-f0-9]{64})(?:;|$)/)?.[1];
 const adminSession=adminToken?await db.prepare("SELECT id_hash FROM sf_admin_sessions WHERE id_hash=? AND expires_at>datetime('now')").bind(await sha(adminToken)).first():null;
 const isAdmin=!!adminSession;
 const adminUser={email:env.ADMIN_EMAIL||'ADMIN'};
 if(request.method==='POST'&&p==='/api/admin/login'){
  if(!request.headers.get('content-type')?.startsWith('application/json'))return err('Invia JSON',415);
  const origin=request.headers.get('origin');if(origin&&origin!==url.origin)return err('Origine non autorizzata',403);
  let b;try{b=await readBody(request)}catch{return err('Dati non validi')}
  if(!env.ADMIN_EMAIL||!env.ADMIN_PASSWORD)return err('Imposta ADMIN_EMAIL e ADMIN_PASSWORD nei Secrets Cloudflare',503);
  const expected=await sha(env.ADMIN_EMAIL.trim().toLowerCase()+'\n'+env.ADMIN_PASSWORD);
  const actual=await sha(String(b.email||'').trim().toLowerCase()+'\n'+String(b.password||''));
  let diff=0;for(let i=0;i<expected.length;i++)diff|=expected.charCodeAt(i)^actual.charCodeAt(i);
  if(diff!==0)return err('Credenziali ADMIN non valide',401);
  const t=token();await db.prepare("INSERT INTO sf_admin_sessions(id_hash,expires_at) VALUES(?,datetime('now','+12 hours'))").bind(await sha(t)).run();
  return json({ok:true},200,{'set-cookie':adminCookie(t,43200)});
 }
 if(request.method==='POST'&&p==='/api/admin/logout'){
  if(adminToken)await db.prepare('DELETE FROM sf_admin_sessions WHERE id_hash=?').bind(await sha(adminToken)).run();
  return json({ok:true},200,{'set-cookie':adminCookie('',0)});
 }
 if(request.method==='GET'&&p==='/api/admin/session')return json({isAdmin});
 if(p.startsWith('/api/admin')){
  if(!isAdmin)return err('Accesso ADMIN non autorizzato',403);
  try{
   if(request.method==='GET'&&p==='/api/admin'){
    const [users,teams,players,events,teamRows,userRows,logs]=await Promise.all([
     db.prepare('SELECT COUNT(*) n FROM users').first(),db.prepare('SELECT COUNT(*) n FROM teams').first(),db.prepare('SELECT COUNT(*) n FROM players').first(),db.prepare('SELECT COUNT(*) n FROM events').first(),
     db.prepare(`SELECT t.id,t.name,t.format,t.created_at,COUNT(DISTINCT p.id) players,COUNT(DISTINCT e.id) events,GROUP_CONCAT(DISTINCT u.email) owners FROM teams t LEFT JOIN players p ON p.team_id=t.id LEFT JOIN events e ON e.team_id=t.id LEFT JOIN team_members m ON m.team_id=t.id AND m.role='owner' LEFT JOIN users u ON u.id=m.user_id GROUP BY t.id ORDER BY t.created_at DESC LIMIT 500`).all(),
     db.prepare(`SELECT u.id,u.email,u.created_at,COUNT(DISTINCT m.team_id) teams FROM users u LEFT JOIN team_members m ON m.user_id=u.id GROUP BY u.id ORDER BY u.created_at DESC LIMIT 500`).all(),
     db.prepare('SELECT actor_email,action,target,created_at FROM admin_audit ORDER BY created_at DESC LIMIT 100').all()]);
    const [subs,banned]=await Promise.all([db.prepare('SELECT * FROM sf_subscriptions').all(),db.prepare('SELECT user_id FROM sf_disabled_users').all()]);const subsMap=new Map(subs.results.map(s=>[s.team_id,s]));const bannedIds=new Set(banned.results.map(x=>x.user_id));const disabled=await db.prepare('SELECT team_id FROM sf_disabled_teams').all();const disabledIds=new Set(disabled.results.map(x=>x.team_id));return json({stats:{users:users.n,teams:teams.n,players:players.n,events:events.n},teams:teamRows.results.map(t=>({...t,disabled:disabledIds.has(t.id),subscription:subsMap.get(t.id)||null})),users:userRows.results.map(u=>({...u,disabled:bannedIds.has(u.id)})),logs:logs.results,subscriptions:{status:'manual',message:'Abbonamenti gestiti manualmente. Stripe non collegato: nessun incasso verificato'}})
   }
   if(request.method==='GET'&&p==='/api/admin/team'){
    let id=url.searchParams.get('id');if(!id)return err('Squadra mancante');let team=await db.prepare('SELECT * FROM teams WHERE id=?').bind(id).first();if(!team)return err('Squadra non trovata',404);
    let [members,players,events]=await Promise.all([db.prepare('SELECT m.role,u.email,u.id FROM team_members m JOIN users u ON u.id=m.user_id WHERE m.team_id=?').bind(id).all(),db.prepare('SELECT id,name,number,role FROM players WHERE team_id=? ORDER BY name').bind(id).all(),db.prepare('SELECT id,title,type,starts_at FROM events WHERE team_id=? ORDER BY starts_at DESC LIMIT 100').bind(id).all()]);return json({team,members:members.results,players:players.results,events:events.results})
   }
   if(request.method==='POST'){
    if(!request.headers.get('content-type')?.startsWith('application/json'))return err('Invia JSON',415);
    const origin=request.headers.get('origin');if(origin&&origin!==url.origin)return err('Origine non autorizzata',403);
    let b;try{b=await readBody(request)}catch{return err('JSON non valido')}
    if(b.op==='adminCreateTeam'){
     const email=clean(b.email,254).toLowerCase(),pass=String(b.password||''),name=clean(b.name,100),format=Number(b.format);
     const plan=['trial','monthly','annual'].includes(b.plan)?b.plan:'trial';
     if(!name)return err('Inserisci il nome della squadra');
     if(![5,7,11].includes(format))return err('Seleziona calcio a 5, 7 oppure 11');
     if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return err('Inserisci una email valida');
     if(pass.length<10||pass.length>200)return err('La password deve avere almeno 10 caratteri');
     const existing=await db.prepare('SELECT id FROM users WHERE lower(email)=?').bind(email).first();
     if(existing)return err('Questa email è già associata a un account. Usane una diversa.',409);
     const userId=uid(),teamId=uid(),salt=token(),hash=await hashPassword(pass,salt);
     const durationDays=plan==='annual'?365:plan==='monthly'?30:14;
     const endsAt=new Date(Date.now()+durationDays*86400000).toISOString().slice(0,19).replace('T',' ');
     const status=plan==='trial'?'trial':'active';
     // D1 batch is atomic. Do not let a nonessential audit insert block account creation.
     try{
      await db.batch([
       db.prepare('INSERT INTO users(id,email,password_hash,salt) VALUES(?,?,?,?)').bind(userId,email,hash,salt),
       db.prepare('INSERT INTO teams(id,name,format) VALUES(?,?,?)').bind(teamId,name,format),
       db.prepare("INSERT INTO team_members(team_id,user_id,role) VALUES(?,?,'owner')").bind(teamId,userId),
       db.prepare('INSERT INTO sf_subscriptions(team_id,plan,status,ends_at) VALUES(?,?,?,?)').bind(teamId,plan,status,endsAt)
      ]);
     }catch(e){
      console.error('ADMIN_CREATE_TEAM_FAILED',e);
      // Only an authenticated ADMIN can reach this branch. Surface the D1 failure
      // to make a schema mismatch actionable instead of hiding it behind a generic 500.
      const detail=String(e?.message||'Errore D1 sconosciuto').slice(0,450);
      return json({error:'Creazione non riuscita nel database: '+detail,code:'ADMIN_CREATE_TEAM_DB'},500);
     }
     try{await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,'create_team',teamId).run()}
     catch(e){console.error('ADMIN_AUDIT_FAILED',e)}
     const saved=await db.prepare('SELECT t.id,t.name,t.format,u.email FROM teams t JOIN team_members m ON m.team_id=t.id JOIN users u ON u.id=m.user_id WHERE t.id=? AND u.id=?').bind(teamId,userId).first();
     if(!saved)return err('La squadra non risulta salvata: riprova o contatta assistenza',500);
     return json({ok:true,team:saved,teamId,userId});
    }
    if(b.op==='adminSubscription'){
     if(!valid(b.teamId,100)||!['trial','monthly','annual','custom'].includes(b.plan)||!['trial','active','past_due','expired','cancelled'].includes(b.status))return err('Piano o stato non valido');
     const team=await db.prepare('SELECT id FROM teams WHERE id=?').bind(b.teamId).first();if(!team)return err('Squadra inesistente',404);
     const ends=String(b.endsAt||'');if(ends&&!/^\d{4}-\d{2}-\d{2}$/.test(ends))return err('Data non valida');
     if(ends&&Number.isNaN(Date.parse(ends+'T00:00:00Z')))return err('Data non valida');
     const notes=clean(b.notes||'',500);
     await db.prepare("INSERT INTO sf_subscriptions(team_id,plan,status,ends_at,notes) VALUES(?,?,?,?,?) ON CONFLICT(team_id) DO UPDATE SET plan=excluded.plan,status=excluded.status,ends_at=excluded.ends_at,notes=excluded.notes,updated_at=CURRENT_TIMESTAMP").bind(b.teamId,b.plan,b.status,ends||null,notes).run();
     await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,'subscription_update',b.teamId).run();return json({ok:true})
    }
    if(b.op==='adminSetUserStatus'){
     if(!valid(b.userId,100)||typeof b.disabled!=='boolean')return err('Dati non validi');
     let u=await db.prepare('SELECT id FROM users WHERE id=?').bind(b.userId).first();if(!u)return err('Utente non trovato',404);
     if(b.disabled){await db.prepare('INSERT OR IGNORE INTO sf_disabled_users(user_id) VALUES(?)').bind(b.userId).run();await db.prepare('DELETE FROM sessions WHERE user_id=?').bind(b.userId).run()}
     else await db.prepare('DELETE FROM sf_disabled_users WHERE user_id=?').bind(b.userId).run();
     await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,b.disabled?'disable_user':'enable_user',b.userId).run();return json({ok:true})
    }
    if(b.op==='adminChangeEmail'){
     const email=clean(b.email,254).toLowerCase();if(!valid(b.userId,100)||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return err('Email non valida');
     let existing=await db.prepare('SELECT id FROM users WHERE email=?').bind(email).first();if(existing&&existing.id!==b.userId)return err('Email già utilizzata',409);
     let r=await db.prepare('UPDATE users SET email=? WHERE id=?').bind(email,b.userId).run();if(!r.meta.changes)return err('Utente non trovato',404);
     await db.prepare('DELETE FROM sessions WHERE user_id=?').bind(b.userId).run();
     await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,'change_email',b.userId).run();return json({ok:true})
    }
    if(b.op==='adminResetPassword'){
     if(!valid(b.userId,100)||!valid(b.password,200)||b.password.length<10)return err('Password di almeno 10 caratteri');
     let salt=token(),h=await hashPassword(b.password,salt);let r=await db.prepare('UPDATE users SET password_hash=?,salt=? WHERE id=?').bind(h,salt,b.userId).run();if(!r.meta.changes)return err('Account non trovato',404);
     await db.prepare('DELETE FROM sessions WHERE user_id=?').bind(b.userId).run();await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,'reset_password',b.userId).run();return json({ok:true})
    }
    if(b.op==='adminSetTeamStatus'){
     if(!valid(b.teamId,100)||typeof b.disabled!=='boolean')return err('Dati non validi');let t=await db.prepare('SELECT id FROM teams WHERE id=?').bind(b.teamId).first();if(!t)return err('Squadra non trovata',404);
     if(b.disabled)await db.prepare('INSERT OR IGNORE INTO sf_disabled_teams(team_id) VALUES(?)').bind(b.teamId).run();else await db.prepare('DELETE FROM sf_disabled_teams WHERE team_id=?').bind(b.teamId).run();
     await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,b.disabled?'disable_team':'enable_team',b.teamId).run();return json({ok:true})
    }
    if(b.op==='adminRevokeSessions'){
     if(!valid(b.userId,100))return err('Utente non valido o sessione ADMIN protetta');
     let found=await db.prepare('SELECT id FROM users WHERE id=?').bind(b.userId).first();if(!found)return err('Utente non trovato',404);
     await db.prepare('DELETE FROM sessions WHERE user_id=?').bind(b.userId).run();
     await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,'revoke_sessions',b.userId).run();return json({ok:true})
    }
    if(b.op==='adminUpdateTeam'){
     if(!valid(b.teamId,100)||!valid(b.name,100)||![5,7,11].includes(Number(b.format)))return err('Dati squadra non validi');
     let team=await db.prepare('SELECT id FROM teams WHERE id=?').bind(b.teamId).first();if(!team)return err('Squadra non trovata',404);
     await db.prepare('UPDATE teams SET name=?,format=? WHERE id=?').bind(clean(b.name,100),Number(b.format),b.teamId).run();
     return json({ok:true});
    }
    if(b.op==='adminRenameTeam'){
     if(!valid(b.teamId,100)||!valid(b.name,100))return err('Dati non validi');
     let r=await db.prepare('UPDATE teams SET name=? WHERE id=?').bind(clean(b.name,100),b.teamId).run();if(!r.meta.changes)return err('Squadra non trovata',404);
     await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,'rename_team',b.teamId).run();return json({ok:true})
    }
    return err('Operazione ADMIN sconosciuta',404)
   }
   return err('Metodo non consentito',405)
  }catch(e){console.error('Admin API',e);return err('Operazione ADMIN non completata: '+String(e?.message||'errore database').slice(0,350),500)}
 }
 if(request.method==='GET'&&p==='/api/me'){let u=await auth(db,request);if(!u)return json({user:null,teams:[]});if(await db.prepare('SELECT 1 FROM sf_disabled_users WHERE user_id=?').bind(u.id).first())return json({user:null,teams:[]});let teams=await db.prepare("SELECT t.*,m.role FROM teams t JOIN team_members m ON t.id=m.team_id WHERE m.user_id=? AND NOT EXISTS (SELECT 1 FROM sf_disabled_teams d WHERE d.team_id=t.id) AND NOT EXISTS (SELECT 1 FROM sf_subscriptions s WHERE s.team_id=t.id AND (s.status IN ('expired','cancelled','past_due') OR (s.ends_at IS NOT NULL AND substr(s.ends_at,1,10)<date('now')))) ORDER BY t.created_at DESC").bind(u.id).all();return json({user:u,teams:teams.results,isAdmin:false})}
 if(request.method==='GET'&&p==='/api/season'){
  let u=await auth(db,request),id=url.searchParams.get('id');if(!await teamAuth(db,u,id))return err('Accesso negato',403);
  const [tactics,progress,finances,fixtures]=await Promise.all([
   db.prepare('SELECT * FROM sf_tactics WHERE team_id=? ORDER BY created_at DESC').bind(id).all(),
   db.prepare('SELECT * FROM sf_progress WHERE team_id=? ORDER BY recorded_at DESC').bind(id).all(),
   db.prepare('SELECT * FROM sf_finances WHERE team_id=? ORDER BY occurred_at DESC').bind(id).all(),
   db.prepare('SELECT * FROM sf_fixtures WHERE team_id=? ORDER BY starts_at').bind(id).all()]);
  return json({tactics:tactics.results,progress:progress.results,finances:finances.results,fixtures:fixtures.results});
 }
 if(request.method==='GET'&&p==='/api/team'){let u=await auth(db,request),id=url.searchParams.get('id');if(!await teamAuth(db,u,id))return err('Accesso non autorizzato',403);let [team,players,events,callups]=await Promise.all([db.prepare('SELECT * FROM teams WHERE id=?').bind(id).first(),db.prepare('SELECT id,name,number,role FROM players WHERE team_id=? ORDER BY name').bind(id).all(),db.prepare('SELECT * FROM events WHERE team_id=? ORDER BY starts_at DESC LIMIT 150').bind(id).all(),db.prepare('SELECT c.event_id,c.player_id,c.status FROM callups c JOIN events e ON e.id=c.event_id WHERE e.team_id=?').bind(id).all()]);let responses=await db.prepare('SELECT a.event_id,a.player_id,a.status FROM availability a JOIN events e ON e.id=a.event_id WHERE e.team_id=?').bind(id).all();return json({team,players:players.results,events:events.results,callups:callups.results,responses:responses.results})}
 if(request.method==='GET'&&p==='/api/event-response'){
  const t=url.searchParams.get('token')||'';if(!/^[a-f0-9]{64}$/.test(t))return err('Link non valido',403);
  const ev=await db.prepare('SELECT e.id,e.title,e.starts_at,e.venue,e.team_id,t.name team_name FROM sf_event_links l JOIN events e ON e.id=l.event_id JOIN teams t ON t.id=e.team_id WHERE l.token_hash=?').bind(await sha(t)).first();
  if(!ev)return err('Link scaduto o inesistente',404);
  if(await db.prepare('SELECT 1 FROM sf_disabled_teams WHERE team_id=?').bind(ev.team_id).first())return err('Squadra sospesa',403);
  let sub=await db.prepare('SELECT status,ends_at FROM sf_subscriptions WHERE team_id=?').bind(ev.team_id).first();if(sub&&(['expired','cancelled','past_due'].includes(sub.status)||(sub.ends_at&&sub.ends_at.slice(0,10)<new Date().toISOString().slice(0,10))))return err('Abbonamento non attivo',403);
  const players=await db.prepare('SELECT p.id,p.name,p.number,a.status FROM players p LEFT JOIN availability a ON a.player_id=p.id AND a.event_id=? WHERE p.team_id=? ORDER BY p.name').bind(ev.id,ev.team_id).all();
  return json({event:{id:ev.id,title:ev.title,starts_at:ev.starts_at,venue:ev.venue,team_name:ev.team_name},players:players.results});
 }
 if(request.method==='GET'&&p==='/api/player'){let t=url.searchParams.get('token');if(!t||!/^[a-f0-9]{64}$/.test(t))return err('Link non valido',403);let player=await db.prepare('SELECT p.id,p.name,p.team_id,t.name AS team_name FROM player_links l JOIN players p ON p.id=l.player_id JOIN teams t ON t.id=p.team_id WHERE l.token_hash=?').bind(await sha(t)).first();if(!player)return err('Link non valido o revocato',403);if(await db.prepare('SELECT 1 FROM sf_disabled_teams WHERE team_id=?').bind(player.team_id).first())return err('Squadra sospesa',403);let ps=await db.prepare('SELECT status,ends_at FROM sf_subscriptions WHERE team_id=?').bind(player.team_id).first();if(ps&&( ['expired','cancelled','past_due'].includes(ps.status)||(ps.ends_at&&ps.ends_at.slice(0,10)<new Date().toISOString().slice(0,10))))return err('Abbonamento squadra non attivo',403);let events=await db.prepare("SELECT e.id,e.title,e.type,e.starts_at,e.venue,e.opponent,a.status AS my_status,c.status AS callup FROM events e LEFT JOIN availability a ON a.event_id=e.id AND a.player_id=? LEFT JOIN callups c ON c.event_id=e.id AND c.player_id=? WHERE e.team_id=? AND e.starts_at>=datetime('now','-1 day') ORDER BY e.starts_at LIMIT 40").bind(player.id,player.id,player.team_id).all();return json({player,events:events.results})}
 if(request.method!=='POST')return err('Metodo non consentito',405);
 if(!request.headers.get('content-type')?.startsWith('application/json'))return err('Invia JSON',415);
 const origin=request.headers.get('origin');if(origin&&origin!==url.origin)return err('Origine non autorizzata',403);
 let b;try{b=await readBody(request)}catch{return err('JSON non valido o troppo grande')}
 const op=b.op;
 try{
 if(op==='register')return err('Registrazione pubblica disabilitata: richiedi l’accesso all’amministratore',403);
 if(op==='login'){let email=clean(b.email,254).toLowerCase(),u=await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first();if(!u||await hashPassword(b.password||'',u.salt)!==u.password_hash)return err('Credenziali non valide',401);if(await db.prepare('SELECT 1 FROM sf_disabled_users WHERE user_id=?').bind(u.id).first())return err('Account disattivato. Contatta ADMIN',403);let active=await db.prepare('SELECT 1 FROM team_members m LEFT JOIN sf_disabled_teams d ON d.team_id=m.team_id WHERE m.user_id=? AND d.team_id IS NULL LIMIT 1').bind(u.id).first();if(!active)return err('Nessuna squadra attiva assegnata',403);let t=token();await db.prepare("INSERT INTO sessions(id_hash,user_id,expires_at) VALUES(?,?,datetime('now','+30 days'))").bind(await sha(t),u.id).run();return json({ok:true},200,{'set-cookie':cookie(t,2592000)})}
 if(op==='eventResponse'){
  if(!/^[a-f0-9]{64}$/.test(b.token||'')||!valid(b.playerId,100)||!['yes','no','maybe'].includes(b.status))return err('Risposta non valida');
  const ev=await db.prepare('SELECT e.id,e.team_id FROM sf_event_links l JOIN events e ON e.id=l.event_id WHERE l.token_hash=?').bind(await sha(b.token)).first();if(!ev)return err('Link non valido',403);
  const pl=await db.prepare('SELECT id FROM players WHERE id=? AND team_id=?').bind(b.playerId,ev.team_id).first();if(!pl)return err('Giocatore non presente nella rosa',403);
  if(await db.prepare('SELECT 1 FROM sf_disabled_teams WHERE team_id=?').bind(ev.team_id).first())return err('Squadra sospesa',403);
  let sub=await db.prepare('SELECT status,ends_at FROM sf_subscriptions WHERE team_id=?').bind(ev.team_id).first();if(sub&&(['expired','cancelled','past_due'].includes(sub.status)||(sub.ends_at&&sub.ends_at.slice(0,10)<new Date().toISOString().slice(0,10))))return err('Abbonamento non attivo',403);
  await db.batch([db.prepare('INSERT INTO availability(event_id,player_id,status,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(event_id,player_id) DO UPDATE SET status=excluded.status,updated_at=CURRENT_TIMESTAMP').bind(ev.id,pl.id,b.status),db.prepare('INSERT INTO sf_availability_log(id,event_id,player_id,status) VALUES(?,?,?,?)').bind(uid(),ev.id,pl.id,b.status)]);
  return json({ok:true});
 }
 if(op==='availability'){let t=b.token;if(typeof t!=='string'||!/^[a-f0-9]{64}$/.test(t)||!['yes','no','maybe'].includes(b.status))return err('Dati non validi');let row=await db.prepare('SELECT p.id,p.team_id FROM player_links l JOIN players p ON p.id=l.player_id WHERE l.token_hash=?').bind(await sha(t)).first();if(!row)return err('Link non valido',403);if(await db.prepare('SELECT 1 FROM sf_disabled_teams WHERE team_id=?').bind(row.team_id).first())return err('Squadra sospesa',403);let asub=await db.prepare('SELECT status,ends_at FROM sf_subscriptions WHERE team_id=?').bind(row.team_id).first();if(asub&&(['expired','cancelled','past_due'].includes(asub.status)||(asub.ends_at&&asub.ends_at.slice(0,10)<new Date().toISOString().slice(0,10))))return err('Abbonamento squadra non attivo',403);let ev=await db.prepare('SELECT id FROM events WHERE id=? AND team_id=?').bind(b.eventId,row.team_id).first();if(!ev)return err('Evento non trovato',404);await db.prepare("INSERT INTO availability(event_id,player_id,status,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(event_id,player_id) DO UPDATE SET status=excluded.status,updated_at=CURRENT_TIMESTAMP").bind(ev.id,row.id,b.status).run();return json({ok:true})}
 let u=await auth(db,request);if(!u)return err('Effettua il login',401);
 if(op==='logout'){let t=(request.headers.get('cookie')||'').match(/sf_session=([a-f0-9]{64})/)?.[1];if(t)await db.prepare('DELETE FROM sessions WHERE id_hash=?').bind(await sha(t)).run();return json({ok:true},200,{'set-cookie':cookie('',0)})}
 if(op==='createTeam')return err('Solo ADMIN può creare squadre',403);
 if(false&&op==='createTeam'){if(!valid(b.name,100)||![5,7,11].includes(Number(b.format)))return err('Nome o formato non valido');let id=uid();await db.batch([db.prepare('INSERT INTO teams(id,name,format) VALUES(?,?,?)').bind(id,clean(b.name,100),Number(b.format)),db.prepare("INSERT INTO team_members(team_id,user_id,role) VALUES(?,?,'owner')").bind(id,u.id)]);return json({ok:true,id})}
 let member=await teamAuth(db,u,b.teamId);if(!member)return err('Non hai accesso a questa squadra',403);
 if(op==='eventLink'){
  const e=await db.prepare('SELECT id FROM events WHERE id=? AND team_id=?').bind(b.eventId,b.teamId).first();if(!e)return err('Evento inesistente',404);
  const t=token();await db.prepare('INSERT INTO sf_event_links(event_id,token_hash) VALUES(?,?) ON CONFLICT(event_id) DO UPDATE SET token_hash=excluded.token_hash,created_at=CURRENT_TIMESTAMP').bind(e.id,await sha(t)).run();return json({ok:true,url:url.origin+'/?event='+t,warning:'Un nuovo link revoca quello precedente.'});
 }
 if(op==='saveTactic'){
  if(!valid(b.title,100)||!valid(b.formation,40)||!['offense','defense','transition','setpiece'].includes(b.phase)||!Array.isArray(b.positions)||b.positions.length>30)return err('Tattica non valida');
  const positions=b.positions.map(x=>({name:clean(x.name,60),x:Math.max(0,Math.min(100,Number(x.x)||0)),y:Math.max(0,Math.min(100,Number(x.y)||0))}));
  const id=uid();await db.prepare('INSERT INTO sf_tactics(id,team_id,title,formation,phase,positions,notes) VALUES(?,?,?,?,?,?,?)').bind(id,b.teamId,clean(b.title,100),clean(b.formation,40),b.phase,JSON.stringify(positions),clean(b.notes,4000)).run();return json({ok:true,id});
 }
 if(op==='saveProgress'){
  if(!valid(b.category,80)||!/^\d{4}-\d{2}-\d{2}$/.test(b.recordedAt||'')||!Number.isInteger(Number(b.score))||Number(b.score)<1||Number(b.score)>10)return err('Valutazione non valida');
  if(b.playerId){let pl=await db.prepare('SELECT id FROM players WHERE id=? AND team_id=?').bind(b.playerId,b.teamId).first();if(!pl)return err('Giocatore non valido',403)}
  let id=uid();await db.prepare('INSERT INTO sf_progress(id,team_id,player_id,recorded_at,category,score,strengths,improvements,action_plan) VALUES(?,?,?,?,?,?,?,?,?)').bind(id,b.teamId,b.playerId||null,b.recordedAt,clean(b.category,80),Number(b.score),clean(b.strengths,2000),clean(b.improvements,2000),clean(b.actionPlan,2000)).run();return json({ok:true,id});
 }
 if(op==='saveFinance'){
  const cents=Math.round(Number(b.amount)*100);if(!['income','expense'].includes(b.kind)||!valid(b.title,150)||!Number.isSafeInteger(cents)||cents<=0||cents>100000000||!/^\d{4}-\d{2}-\d{2}$/.test(b.occurredAt||''))return err('Movimento non valido');
  if(b.playerId){let pl=await db.prepare('SELECT id FROM players WHERE id=? AND team_id=?').bind(b.playerId,b.teamId).first();if(!pl)return err('Giocatore non valido',403)}
  let id=uid();await db.prepare('INSERT INTO sf_finances(id,team_id,player_id,kind,amount_cents,title,occurred_at,notes) VALUES(?,?,?,?,?,?,?,?)').bind(id,b.teamId,b.playerId||null,b.kind,cents,clean(b.title,150),b.occurredAt,clean(b.notes,1000)).run();return json({ok:true,id});
 }
 if(op==='saveFixture'){
  if(!valid(b.opponent,120)||!valid(b.competition,120)||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(b.startsAt||''))return err('Dati partita non validi');
  const gf=b.goalsFor===''||b.goalsFor==null?null:Number(b.goalsFor),ga=b.goalsAgainst===''||b.goalsAgainst==null?null:Number(b.goalsAgainst);
  if([gf,ga].some(x=>x!==null&&(!Number.isInteger(x)||x<0||x>99)))return err('Risultato non valido');
  let id=uid();await db.prepare('INSERT INTO sf_fixtures(id,team_id,competition,round,opponent,starts_at,venue,home,goals_for,goals_against,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(id,b.teamId,clean(b.competition,120),clean(b.round,40),clean(b.opponent,120),b.startsAt,clean(b.venue,120),b.home?1:0,gf,ga,clean(b.source,300)).run();return json({ok:true,id});
 }
 if(op==='deleteSeasonItem'){
  const tables={tactic:'sf_tactics',progress:'sf_progress',finance:'sf_finances',fixture:'sf_fixtures'};const table=tables[b.kind];if(!table||!valid(b.id,100))return err('Elemento non valido');
  const r=await db.prepare('DELETE FROM '+table+' WHERE id=? AND team_id=?').bind(b.id,b.teamId).run();return json({ok:r.meta.changes>0});
 }
 if(op==='addPlayer'){if(!valid(b.name,100))return err('Inserisci il nome');let number=b.number===''||b.number==null?null:Number(b.number);if(number!==null&&(!Number.isInteger(number)||number<0||number>99))return err('Numero maglia non valido');let id=uid();await db.prepare('INSERT INTO players(id,team_id,name,number,role) VALUES(?,?,?,?,?)').bind(id,b.teamId,clean(b.name,100),number,clean(b.role,50)).run();return json({ok:true,id})}
 if(op==='deletePlayer'){let r=await db.prepare('DELETE FROM players WHERE id=? AND team_id=?').bind(b.playerId,b.teamId).run();return json({ok:r.meta.changes>0})}
 if(op==='addEvent'){if(!valid(b.title,120)||!['training','match','other'].includes(b.type)||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(b.startsAt))return err('Dati evento non validi');let id=uid();await db.prepare('INSERT INTO events(id,team_id,type,title,starts_at,venue,opponent) VALUES(?,?,?,?,?,?,?)').bind(id,b.teamId,b.type,clean(b.title,120),b.startsAt,clean(b.venue,120),clean(b.opponent,120)).run();return json({ok:true,id})}
 if(op==='deleteEvent'){let r=await db.prepare('DELETE FROM events WHERE id=? AND team_id=?').bind(b.eventId,b.teamId).run();return json({ok:r.meta.changes>0})}
 if(op==='setCallup'){if(!['called','reserve','none'].includes(b.status))return err('Stato non valido');let ev=await db.prepare('SELECT id FROM events WHERE id=? AND team_id=?').bind(b.eventId,b.teamId).first(),pl=await db.prepare('SELECT id FROM players WHERE id=? AND team_id=?').bind(b.playerId,b.teamId).first();if(!ev||!pl)return err('Giocatore o evento non trovato',404);if(b.status==='none')await db.prepare('DELETE FROM callups WHERE event_id=? AND player_id=?').bind(ev.id,pl.id).run();else await db.prepare('INSERT INTO callups(event_id,player_id,status) VALUES(?,?,?) ON CONFLICT(event_id,player_id) DO UPDATE SET status=excluded.status').bind(ev.id,pl.id,b.status).run();return json({ok:true})}
 if(op==='playerLink'){let pl=await db.prepare('SELECT id FROM players WHERE id=? AND team_id=?').bind(b.playerId,b.teamId).first();if(!pl)return err('Giocatore non trovato',404);let t=token();await db.prepare('INSERT INTO player_links(player_id,token_hash) VALUES(?,?) ON CONFLICT(player_id) DO UPDATE SET token_hash=excluded.token_hash,created_at=CURRENT_TIMESTAMP').bind(pl.id,await sha(t)).run();return json({ok:true,url:`${url.origin}/?player=${t}`,warning:'Il precedente link è stato revocato. Conserva il nuovo link: non sarà recuperabile.'})}
 return err('Operazione sconosciuta',404)
 }catch(e){console.error('SquadraFacile API:',e);return err('Operazione non riuscita. Verifica il database e riprova.',500)}
}
