const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...headers}});
const err=(message,status=400)=>json({error:message},status);
const uid=()=>crypto.randomUUID();
const token=()=>{let b=new Uint8Array(32);crypto.getRandomValues(b);return Array.from(b,x=>x.toString(16).padStart(2,'0')).join('')};
const sha=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s))),x=>x.toString(16).padStart(2,'0')).join('');
const hex=a=>Array.from(a,x=>x.toString(16).padStart(2,'0')).join('');
async function hashPassword(pass,salt){let k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pass),'PBKDF2',false,['deriveBits']);return hex(new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:210000,hash:'SHA-256'},k,256)))}
const valid=(v,n=150)=>typeof v==='string'&&v.trim().length>0&&v.trim().length<=n;
const clean=(v,n=150)=>typeof v==='string'?v.trim().slice(0,n):'';
async function auth(db,request){let c=request.headers.get('cookie')||'';let t=c.match(/(?:^|;\s*)sf_session=([a-f0-9]{64})(?:;|$)/)?.[1];if(!t)return null;return db.prepare("SELECT users.id,users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.id_hash=? AND sessions.expires_at>datetime('now') AND NOT EXISTS (SELECT 1 FROM sf_disabled_users du WHERE du.user_id=users.id)").bind(await sha(t)).first()}
const adminCookie=(t,maxAge)=>`sf_admin=${t}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const cookie=(t,maxAge)=>`sf_session=${t}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
async function teamAuth(db,user,teamId){if(!user||!teamId)return null;let disabled=await db.prepare('SELECT 1 FROM sf_disabled_teams WHERE team_id=?').bind(teamId).first();if(disabled)return null;let banned=await db.prepare('SELECT 1 FROM sf_disabled_users WHERE user_id=?').bind(user.id).first();if(banned)return null;return db.prepare('SELECT role FROM team_members WHERE team_id=? AND user_id=?').bind(teamId,user.id).first()}
async function readBody(req){let len=Number(req.headers.get('content-length')||0);if(len>16000)throw Error('Richiesta troppo grande');return req.json()}
export async function onRequest({request,env}){
 const url=new URL(request.url),p=url.pathname;
 if(!p.startsWith('/api/'))return env.ASSETS.fetch(request);
 if(!env.DB)return err('Database D1 non collegato: aggiungi il binding DB su Cloudflare Pages.',503);
 const db=env.DB;
 // Ensure ADMIN-only tables exist before checking sessions or accepting login.
 // This makes first-time setup safe without a manual D1 migration.
 if(p.startsWith('/api/admin')){
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
     let email=clean(b.email,254).toLowerCase(),pass=b.password,name=clean(b.name,100),format=Number(b.format);
     if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!valid(pass,200)||pass.length<10||!name||![5,7,11].includes(format))return err('Inserisci squadra, formato, email e password di almeno 10 caratteri');
     let user=await db.prepare('SELECT id FROM users WHERE email=?').bind(email).first();let userId=user?.id||uid(),teamId=uid();
     if(!user){let salt=token(),h=await hashPassword(pass,salt);await db.prepare('INSERT INTO users(id,email,password_hash,salt) VALUES(?,?,?,?)').bind(userId,email,h,salt).run()}
     else return err('Email già presente: utilizza un indirizzo diverso',409);
     await db.batch([db.prepare('INSERT INTO teams(id,name,format) VALUES(?,?,?)').bind(teamId,name,format),db.prepare("INSERT INTO team_members(team_id,user_id,role) VALUES(?,?,'owner')").bind(teamId,userId),db.prepare("INSERT INTO sf_subscriptions(team_id,plan,status,ends_at) VALUES(?,'trial','trial',datetime('now','+14 days'))").bind(teamId)]);
     await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,'create_team',teamId).run();return json({ok:true,teamId})
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
    if(b.op==='adminRenameTeam'){
     if(!valid(b.teamId,100)||!valid(b.name,100))return err('Dati non validi');
     let r=await db.prepare('UPDATE teams SET name=? WHERE id=?').bind(clean(b.name,100),b.teamId).run();if(!r.meta.changes)return err('Squadra non trovata',404);
     await db.prepare('INSERT INTO admin_audit(id,actor_email,action,target) VALUES(?,?,?,?)').bind(uid(),adminUser.email,'rename_team',b.teamId).run();return json({ok:true})
    }
    return err('Operazione ADMIN sconosciuta',404)
   }
   return err('Metodo non consentito',405)
  }catch(e){console.error('Admin API',e);return err('ADMIN non configurato: esegui admin-migration.sql su D1.',503)}
 }
 if(request.method==='GET'&&p==='/api/me'){let u=await auth(db,request);if(!u)return json({user:null,teams:[]});if(await db.prepare('SELECT 1 FROM sf_disabled_users WHERE user_id=?').bind(u.id).first())return json({user:null,teams:[]});let teams=await db.prepare('SELECT t.*,m.role FROM teams t JOIN team_members m ON t.id=m.team_id WHERE m.user_id=? AND NOT EXISTS (SELECT 1 FROM sf_disabled_teams d WHERE d.team_id=t.id) ORDER BY t.created_at DESC').bind(u.id).all();return json({user:u,teams:teams.results,isAdmin:false})}
 if(request.method==='GET'&&p==='/api/team'){let u=await auth(db,request),id=url.searchParams.get('id');if(!await teamAuth(db,u,id))return err('Accesso non autorizzato',403);let [team,players,events,callups]=await Promise.all([db.prepare('SELECT * FROM teams WHERE id=?').bind(id).first(),db.prepare('SELECT id,name,number,role FROM players WHERE team_id=? ORDER BY name').bind(id).all(),db.prepare('SELECT * FROM events WHERE team_id=? ORDER BY starts_at DESC LIMIT 150').bind(id).all(),db.prepare('SELECT c.event_id,c.player_id,c.status FROM callups c JOIN events e ON e.id=c.event_id WHERE e.team_id=?').bind(id).all()]);let responses=await db.prepare('SELECT a.event_id,a.player_id,a.status FROM availability a JOIN events e ON e.id=a.event_id WHERE e.team_id=?').bind(id).all();return json({team,players:players.results,events:events.results,callups:callups.results,responses:responses.results})}
 if(request.method==='GET'&&p==='/api/player'){let t=url.searchParams.get('token');if(!t||!/^[a-f0-9]{64}$/.test(t))return err('Link non valido',403);let player=await db.prepare('SELECT p.id,p.name,p.team_id,t.name AS team_name FROM player_links l JOIN players p ON p.id=l.player_id JOIN teams t ON t.id=p.team_id WHERE l.token_hash=?').bind(await sha(t)).first();if(!player)return err('Link non valido o revocato',403);if(await db.prepare('SELECT 1 FROM sf_disabled_teams WHERE team_id=?').bind(player.team_id).first())return err('Squadra sospesa',403);let events=await db.prepare("SELECT e.id,e.title,e.type,e.starts_at,e.venue,e.opponent,a.status AS my_status,c.status AS callup FROM events e LEFT JOIN availability a ON a.event_id=e.id AND a.player_id=? LEFT JOIN callups c ON c.event_id=e.id AND c.player_id=? WHERE e.team_id=? AND e.starts_at>=datetime('now','-1 day') ORDER BY e.starts_at LIMIT 40").bind(player.id,player.id,player.team_id).all();return json({player,events:events.results})}
 if(request.method!=='POST')return err('Metodo non consentito',405);
 if(!request.headers.get('content-type')?.startsWith('application/json'))return err('Invia JSON',415);
 const origin=request.headers.get('origin');if(origin&&origin!==url.origin)return err('Origine non autorizzata',403);
 let b;try{b=await readBody(request)}catch{return err('JSON non valido o troppo grande')}
 const op=b.op;
 try{
 if(op==='register')return err('Registrazione pubblica disabilitata: richiedi l’accesso all’amministratore',403);
 if(op==='login'){let email=clean(b.email,254).toLowerCase(),u=await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first();if(!u||await hashPassword(b.password||'',u.salt)!==u.password_hash)return err('Credenziali non valide',401);if(await db.prepare('SELECT 1 FROM sf_disabled_users WHERE user_id=?').bind(u.id).first())return err('Account disattivato. Contatta ADMIN',403);let active=await db.prepare('SELECT 1 FROM team_members m LEFT JOIN sf_disabled_teams d ON d.team_id=m.team_id WHERE m.user_id=? AND d.team_id IS NULL LIMIT 1').bind(u.id).first();if(!active)return err('Nessuna squadra attiva assegnata',403);let t=token();await db.prepare("INSERT INTO sessions(id_hash,user_id,expires_at) VALUES(?,?,datetime('now','+30 days'))").bind(await sha(t),u.id).run();return json({ok:true},200,{'set-cookie':cookie(t,2592000)})}
 if(op==='availability'){let t=b.token;if(typeof t!=='string'||!/^[a-f0-9]{64}$/.test(t)||!['yes','no','maybe'].includes(b.status))return err('Dati non validi');let row=await db.prepare('SELECT p.id,p.team_id FROM player_links l JOIN players p ON p.id=l.player_id WHERE l.token_hash=?').bind(await sha(t)).first();if(!row)return err('Link non valido',403);if(await db.prepare('SELECT 1 FROM sf_disabled_teams WHERE team_id=?').bind(row.team_id).first())return err('Squadra sospesa',403);let ev=await db.prepare('SELECT id FROM events WHERE id=? AND team_id=?').bind(b.eventId,row.team_id).first();if(!ev)return err('Evento non trovato',404);await db.prepare("INSERT INTO availability(event_id,player_id,status,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(event_id,player_id) DO UPDATE SET status=excluded.status,updated_at=CURRENT_TIMESTAMP").bind(ev.id,row.id,b.status).run();return json({ok:true})}
 let u=await auth(db,request);if(!u)return err('Effettua il login',401);
 if(op==='logout'){let t=(request.headers.get('cookie')||'').match(/sf_session=([a-f0-9]{64})/)?.[1];if(t)await db.prepare('DELETE FROM sessions WHERE id_hash=?').bind(await sha(t)).run();return json({ok:true},200,{'set-cookie':cookie('',0)})}
 if(op==='createTeam')return err('Solo ADMIN può creare squadre',403);
 if(false&&op==='createTeam'){if(!valid(b.name,100)||![5,7,11].includes(Number(b.format)))return err('Nome o formato non valido');let id=uid();await db.batch([db.prepare('INSERT INTO teams(id,name,format) VALUES(?,?,?)').bind(id,clean(b.name,100),Number(b.format)),db.prepare("INSERT INTO team_members(team_id,user_id,role) VALUES(?,?,'owner')").bind(id,u.id)]);return json({ok:true,id})}
 let member=await teamAuth(db,u,b.teamId);if(!member)return err('Non hai accesso a questa squadra',403);
 if(op==='addPlayer'){if(!valid(b.name,100))return err('Inserisci il nome');let number=b.number===''||b.number==null?null:Number(b.number);if(number!==null&&(!Number.isInteger(number)||number<0||number>99))return err('Numero maglia non valido');let id=uid();await db.prepare('INSERT INTO players(id,team_id,name,number,role) VALUES(?,?,?,?,?)').bind(id,b.teamId,clean(b.name,100),number,clean(b.role,50)).run();return json({ok:true,id})}
 if(op==='deletePlayer'){let r=await db.prepare('DELETE FROM players WHERE id=? AND team_id=?').bind(b.playerId,b.teamId).run();return json({ok:r.meta.changes>0})}
 if(op==='addEvent'){if(!valid(b.title,120)||!['training','match','other'].includes(b.type)||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(b.startsAt))return err('Dati evento non validi');let id=uid();await db.prepare('INSERT INTO events(id,team_id,type,title,starts_at,venue,opponent) VALUES(?,?,?,?,?,?,?)').bind(id,b.teamId,b.type,clean(b.title,120),b.startsAt,clean(b.venue,120),clean(b.opponent,120)).run();return json({ok:true,id})}
 if(op==='deleteEvent'){let r=await db.prepare('DELETE FROM events WHERE id=? AND team_id=?').bind(b.eventId,b.teamId).run();return json({ok:r.meta.changes>0})}
 if(op==='setCallup'){if(!['called','reserve','none'].includes(b.status))return err('Stato non valido');let ev=await db.prepare('SELECT id FROM events WHERE id=? AND team_id=?').bind(b.eventId,b.teamId).first(),pl=await db.prepare('SELECT id FROM players WHERE id=? AND team_id=?').bind(b.playerId,b.teamId).first();if(!ev||!pl)return err('Giocatore o evento non trovato',404);if(b.status==='none')await db.prepare('DELETE FROM callups WHERE event_id=? AND player_id=?').bind(ev.id,pl.id).run();else await db.prepare('INSERT INTO callups(event_id,player_id,status) VALUES(?,?,?) ON CONFLICT(event_id,player_id) DO UPDATE SET status=excluded.status').bind(ev.id,pl.id,b.status).run();return json({ok:true})}
 if(op==='playerLink'){let pl=await db.prepare('SELECT id FROM players WHERE id=? AND team_id=?').bind(b.playerId,b.teamId).first();if(!pl)return err('Giocatore non trovato',404);let t=token();await db.prepare('INSERT INTO player_links(player_id,token_hash) VALUES(?,?) ON CONFLICT(player_id) DO UPDATE SET token_hash=excluded.token_hash,created_at=CURRENT_TIMESTAMP').bind(pl.id,await sha(t)).run();return json({ok:true,url:`${url.origin}/?player=${t}`,warning:'Il precedente link è stato revocato. Conserva il nuovo link: non sarà recuperabile.'})}
 return err('Operazione sconosciuta',404)
 }catch(e){console.error('SquadraFacile API:',e);return err('Operazione non riuscita. Verifica il database e riprova.',500)}
}
