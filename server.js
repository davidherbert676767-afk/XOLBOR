import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import crypto from 'crypto';

const app = express();
const port = Number(process.env.PORT || 8080);
const jwtSecret = process.env.JWT_SECRET || 'dev-only-change-me';
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '256kb' }));

const db = new Database(process.env.DB_FILE || './xolbor.sqlite');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'PLAYER',
  coins INTEGER NOT NULL DEFAULT 1250,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS games (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  icon TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  game_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bans (
  user_id TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS game_roles (
  game_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY(game_id,user_id)
);
CREATE TABLE IF NOT EXISTS friendships (
  requester_id TEXT NOT NULL,
  addressee_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_at INTEGER NOT NULL,
  PRIMARY KEY(requester_id, addressee_id)
);
CREATE TABLE IF NOT EXISTS game_rooms (
  room_id TEXT PRIMARY KEY,
  game_key TEXT NOT NULL,
  max_players INTEGER NOT NULL DEFAULT 12,
  created_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN'
);
CREATE TABLE IF NOT EXISTS room_players (
  room_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  joined_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY(room_id,user_id)
);
`);

const now = () => Date.now();
const seedGames = [
  ['1','Cube Lift 3D','Levante o cubo gigante','🧊'],['2','Phoenix Pet Ride 3D','Monte um pet lendário','🔥'],
  ['3','Neon Drives 3D','Construa e pilote','🏎️'],['4','Sky Rails 3D','Corra pelos trilhos','🎢'],
  ['5','Treasure Island 3D','Encontre tesouros escondidos','🏝️'],['6','Zombie Escape 3D','Escape antes do tempo acabar','🧟'],
  ['7','Space Builders 3D','Construa sua base espacial','🚀'],['8','Volcano Run 3D','Corra da lava','🌋'],
  ['9','Pet World 3D','Cuide e evolua seus pets','🐾'],['10','Battle Arena 3D','Desafie outros jogadores','⚔️']
];
for (const [id,name,description,icon] of seedGames) {
  db.prepare('INSERT OR IGNORE INTO games(id,name,description,icon,owner_id,created_at) VALUES(?,?,?,?,?,?)').run(id,name,description,icon,'SYSTEM',now());
}

// If the deployment defines OWNER_EMAIL, keep that existing account as the owner.
const ownerEmail = String(process.env.OWNER_EMAIL || '').trim().toLowerCase();
if (ownerEmail) {
  db.prepare("UPDATE users SET role='OWNER' WHERE lower(email)=?").run(ownerEmail);
}

const publicUser = u => ({ id: u.id, email: u.email, username: u.username, role: u.role, coins: u.coins });
const sign = u => jwt.sign({ sub: u.id }, jwtSecret, { expiresIn: '30d' });

function auth(req, res, next) {
  const raw = req.headers.authorization || '';
  if (!raw.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autenticado.' });
  try {
    const payload = jwt.verify(raw.slice(7), jwtSecret);
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(payload.sub);
    if (!u) return res.status(401).json({ error: 'Conta não encontrada.' });
    // OWNER_EMAIL is authoritative for the owner account. Re-check it on every authenticated request
    // so an account created before the environment variable was added is promoted automatically.
    if (ownerEmail && String(u.email).trim().toLowerCase() === ownerEmail && u.role !== 'OWNER') {
      db.prepare("UPDATE users SET role='OWNER' WHERE id=?").run(u.id);
      u.role = 'OWNER';
    }
    if (db.prepare('SELECT 1 FROM bans WHERE user_id=?').get(u.id)) return res.status(403).json({ error: 'Conta banida.' });
    req.user = u;
    next();
  } catch { return res.status(401).json({ error: 'Sessão inválida.' }); }
}

function ownerOnly(req, res, next) {
  if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Somente o dono do XOLBOR pode usar esta função.' });
  next();
}


const GAME_LIMITS = { tower: 12, disasters: 20, ether: 15, neon: 8 };

app.get('/rooms', auth, (req,res) => {
  const game = String(req.query.game || '').trim();
  if (!GAME_LIMITS[game]) return res.status(400).json({error:'Jogo inválido.'});
  const cutoff = now() - 30000;
  db.prepare('DELETE FROM room_players WHERE last_seen < ?').run(cutoff);
  const rows = db.prepare(`SELECT r.room_id,r.game_key,r.max_players,r.status,COUNT(p.user_id) players
    FROM game_rooms r LEFT JOIN room_players p ON p.room_id=r.room_id
    WHERE r.game_key=? AND r.status='OPEN'
    GROUP BY r.room_id ORDER BY r.created_at ASC LIMIT 50`).all(game);
  res.json({rooms: rows.map(r => ({roomId:r.room_id,game:r.game_key,players:r.players,maxPlayers:r.max_players,status:r.status}))});
});

app.post('/rooms', auth, (req,res) => {
  const game = String(req.body.game || '').trim();
  const maxPlayers = GAME_LIMITS[game];
  if (!maxPlayers) return res.status(400).json({error:'Jogo inválido.'});
  const cutoff = now() - 30000;
  db.prepare('DELETE FROM room_players WHERE last_seen < ?').run(cutoff);
  const open = db.prepare(`SELECT r.room_id,r.max_players,COUNT(p.user_id) players FROM game_rooms r LEFT JOIN room_players p ON p.room_id=r.room_id WHERE r.game_key=? AND r.status='OPEN' GROUP BY r.room_id HAVING players < r.max_players ORDER BY r.created_at ASC LIMIT 1`).get(game);
  const roomId = open?.room_id || crypto.randomUUID();
  if (!open) db.prepare('INSERT INTO game_rooms(room_id,game_key,max_players,created_at,status) VALUES(?,?,?,?,?)').run(roomId,game,maxPlayers,now(),'OPEN');
  db.prepare('INSERT OR REPLACE INTO room_players(room_id,user_id,joined_at,last_seen) VALUES(?,?,COALESCE((SELECT joined_at FROM room_players WHERE room_id=? AND user_id=?),?),?)').run(roomId,req.user.id,roomId,req.user.id,now(),now());
  res.status(201).json({roomId,game,players:db.prepare('SELECT COUNT(*) c FROM room_players WHERE room_id=?').get(roomId).c,maxPlayers});
});

app.post('/rooms/:roomId/join', auth, (req,res) => {
  const room = db.prepare('SELECT * FROM game_rooms WHERE room_id=? AND status='OPEN'').get(req.params.roomId);
  if (!room) return res.status(404).json({error:'Sala não encontrada.'});
  const cutoff = now() - 30000; db.prepare('DELETE FROM room_players WHERE last_seen < ?').run(cutoff);
  const count = db.prepare('SELECT COUNT(*) c FROM room_players WHERE room_id=?').get(room.room_id).c;
  if (count >= room.max_players) return res.status(409).json({error:'Sala cheia.'});
  db.prepare('INSERT OR REPLACE INTO room_players(room_id,user_id,joined_at,last_seen) VALUES(?,?,COALESCE((SELECT joined_at FROM room_players WHERE room_id=? AND user_id=?),?),?)').run(room.room_id,req.user.id,room.room_id,req.user.id,now(),now());
  res.json({roomId:room.room_id,game:room.game_key,players:db.prepare('SELECT COUNT(*) c FROM room_players WHERE room_id=?').get(room.room_id).c,maxPlayers:room.max_players});
});

app.post('/rooms/:roomId/heartbeat', auth, (req,res) => {
  const changed=db.prepare('UPDATE room_players SET last_seen=? WHERE room_id=? AND user_id=?').run(now(),req.params.roomId,req.user.id);
  if (!changed.changes) return res.status(404).json({error:'Você não está nessa sala.'});
  const players=db.prepare('SELECT COUNT(*) c FROM room_players WHERE room_id=?').get(req.params.roomId).c;
  res.json({ok:true,players});
});

app.get('/health', (_req,res) => res.json({ ok:true, service:'xolbor-backend', time:now() }));

app.post('/auth/signup', async (req,res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({error:'E-mail inválido.'});
  if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) return res.status(400).json({error:'Nome de usuário: 3–24 caracteres, letras, números e _.'});
  if (password.length < 8) return res.status(400).json({error:'A senha precisa ter pelo menos 8 caracteres.'});
  if (db.prepare('SELECT 1 FROM users WHERE email=? OR username=?').get(email,username)) return res.status(409).json({error:'E-mail ou usuário já cadastrado.'});
  const id = crypto.randomUUID();
  const role = ownerEmail && email === ownerEmail ? 'OWNER' : 'PLAYER';
  const hash = await bcrypt.hash(password, 12);
  db.prepare('INSERT INTO users(id,email,username,password_hash,role,coins,created_at) VALUES(?,?,?,?,?,?,?)').run(id,email,username,hash,role,1250,now());
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  res.status(201).json({ token: sign(u), user: publicUser(u) });
});

app.post('/auth/login', async (req,res) => {
  const identifier = String(req.body.identifier || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const u = db.prepare('SELECT * FROM users WHERE lower(email)=? OR lower(username)=?').get(identifier,identifier);
  if (!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Usuário/e-mail ou senha incorretos.'});
  if (db.prepare('SELECT 1 FROM bans WHERE user_id=?').get(u.id)) return res.status(403).json({error:'Conta banida.'});
  res.json({ token: sign(u), user: publicUser(u) });
});

app.post('/auth/create-owner', async (req,res) => {
  const setupKey = req.headers['x-owner-setup-key'];
  if (!setupKey || setupKey !== process.env.OWNER_SETUP_KEY) return res.status(403).json({error:'Chave de configuração inválida.'});
  const email = String(req.body.email||'').trim().toLowerCase();
  const username = String(req.body.username||'').trim();
  const password = String(req.body.password||'');
  if (!/^\S+@\S+\.\S+$/.test(email) || !/^[A-Za-z0-9_]{3,24}$/.test(username) || password.length < 8) return res.status(400).json({error:'Dados do dono inválidos.'});
  if (db.prepare('SELECT 1 FROM users WHERE email=? OR username=?').get(email,username)) return res.status(409).json({error:'Conta já existe.'});
  const id=crypto.randomUUID(); const hash=await bcrypt.hash(password,12);
  db.prepare('INSERT INTO users(id,email,username,password_hash,role,coins,created_at) VALUES(?,?,?,?,?,?,?)').run(id,email,username,hash,'OWNER',1250,now());
  const u=db.prepare('SELECT * FROM users WHERE id=?').get(id); res.status(201).json({token:sign(u),user:publicUser(u)});
});

app.get('/me', auth, (req,res) => res.json({user: publicUser(req.user)}));

app.get('/games', (_req,res) => {
  const games = db.prepare(`SELECT g.id,g.name,g.description,g.icon,g.owner_id,g.created_at,u.username owner_username
    FROM games g JOIN users u ON u.id=g.owner_id ORDER BY g.created_at DESC`).all();
  res.json({games});
});

app.post('/games', auth, (req,res) => {
  const name = String(req.body.name || '').trim().slice(0,40);
  const description = String(req.body.description || '').trim().slice(0,200);
  const icon = String(req.body.icon || '🎮').slice(0,8);
  if (name.length < 3 || description.length < 5) return res.status(400).json({error:'Nome ou descrição inválidos.'});
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO games(id,name,description,icon,owner_id,created_at) VALUES(?,?,?,?,?,?)').run(id,name,description,icon,req.user.id,now());
  res.status(201).json({game:{id,name,description,icon,owner_id:req.user.id,owner_username:req.user.username}});
});

app.get('/games/:gameId/chat', auth, (req,res) => {
  const after = Number(req.query.after || 0);
  const messages = db.prepare(`SELECT id,username,text,created_at FROM chat_messages WHERE game_id=? AND id>? ORDER BY id ASC LIMIT 100`).all(req.params.gameId,after);
  res.json({messages});
});

const blocked = ['palavra-proibida-exemplo'];
function cleanChat(t) {
  let s = String(t || '').trim().slice(0,240);
  for (const w of blocked) s = s.replace(new RegExp(w,'gi'),'***');
  return s;
}
app.post('/games/:gameId/chat', auth, (req,res) => {
  const text = cleanChat(req.body.text);
  if (!text) return res.status(400).json({error:'Mensagem vazia.'});
  const exists = db.prepare('SELECT 1 FROM games WHERE id=?').get(req.params.gameId);
  if (!exists) return res.status(404).json({error:'Jogo não encontrado.'});
  const result = db.prepare('INSERT INTO chat_messages(game_id,user_id,username,text,created_at) VALUES(?,?,?,?,?)').run(req.params.gameId,req.user.id,req.user.username,text,now());
  res.status(201).json({id:result.lastInsertRowid});
});


app.get('/friends', auth, (req,res) => {
  const rows = db.prepare(`
    SELECT f.requester_id, f.addressee_id, f.status, f.created_at,
           r.username requester_username, a.username addressee_username,
           r.role requester_role, a.role addressee_role
    FROM friendships f
    JOIN users r ON r.id=f.requester_id
    JOIN users a ON a.id=f.addressee_id
    WHERE f.requester_id=? OR f.addressee_id=?
    ORDER BY f.created_at DESC`).all(req.user.id, req.user.id);
  const friends = rows.filter(x => x.status === 'ACCEPTED').map(x => ({
    username: x.requester_id === req.user.id ? x.addressee_username : x.requester_username,
    role: x.requester_id === req.user.id ? x.addressee_role : x.requester_role,
    status: 'Amigo'
  }));
  const incoming = rows.filter(x => x.status === 'PENDING' && x.addressee_id === req.user.id).map(x => ({username:x.requester_username}));
  const outgoing = rows.filter(x => x.status === 'PENDING' && x.requester_id === req.user.id).map(x => ({username:x.addressee_username}));
  res.json({friends,incoming,outgoing});
});

app.post('/friends/request', auth, (req,res) => {
  const username = String(req.body.username || '').trim();
  const target = db.prepare('SELECT id,username FROM users WHERE lower(username)=lower(?)').get(username);
  if (!target) return res.status(404).json({error:'Jogador não encontrado.'});
  if (target.id === req.user.id) return res.status(400).json({error:'Você não pode adicionar a si mesmo.'});
  const existing = db.prepare(`SELECT * FROM friendships WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)`).get(req.user.id,target.id,target.id,req.user.id);
  if (existing) return res.status(409).json({error:'Já existe uma solicitação ou amizade com esse jogador.'});
  db.prepare('INSERT INTO friendships(requester_id,addressee_id,status,created_at) VALUES(?,?,?,?)').run(req.user.id,target.id,'PENDING',now());
  res.status(201).json({ok:true});
});

app.post('/friends/accept', auth, (req,res) => {
  const username = String(req.body.username || '').trim();
  const target = db.prepare('SELECT id FROM users WHERE lower(username)=lower(?)').get(username);
  if (!target) return res.status(404).json({error:'Jogador não encontrado.'});
  const result = db.prepare("UPDATE friendships SET status='ACCEPTED' WHERE requester_id=? AND addressee_id=? AND status='PENDING'").run(target.id,req.user.id);
  if (!result.changes) return res.status(404).json({error:'Solicitação não encontrada.'});
  res.json({ok:true});
});

app.get('/players', auth, (req,res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 2) return res.json({users:[]});
  const users = db.prepare("SELECT username, role FROM users WHERE id<>? AND lower(username) LIKE lower(?) ORDER BY username LIMIT 20").all(req.user.id, `%${q}%`);
  res.json({users});
});

app.get('/admin/users', auth, ownerOnly, (_req,res) => {
  const users = db.prepare('SELECT id,email,username,role,coins,created_at FROM users ORDER BY created_at DESC LIMIT 500').all();
  res.json({users});
});

app.post('/wallet/spend', auth, (req,res) => {
  const amount = Number(req.body.amount);
  const reason = String(req.body.reason || 'purchase').slice(0,80);
  if (!Number.isInteger(amount) || amount <= 0 || amount > 1000000) return res.status(400).json({error:'Valor inválido.'});
  const tx = db.transaction(() => {
    const u = db.prepare('SELECT coins FROM users WHERE id=?').get(req.user.id);
    if (u.coins < amount) throw new Error('Moedas insuficientes.');
    db.prepare('UPDATE users SET coins=coins-? WHERE id=?').run(amount,req.user.id);
    return db.prepare('SELECT coins FROM users WHERE id=?').get(req.user.id).coins;
  });
  try { const coins=tx(); res.json({coins,reason}); } catch(e) { res.status(400).json({error:e.message}); }
});

app.post('/admin/ban', auth, ownerOnly, (req,res) => {
  const username = String(req.body.username || '').trim();
  const target = db.prepare('SELECT * FROM users WHERE lower(username)=lower(?)').get(username);
  if (!target) return res.status(404).json({error:'Usuário não encontrado.'});
  if (target.role === 'OWNER') return res.status(403).json({error:'O dono do XOLBOR não pode ser banido.'});
  db.prepare('INSERT OR REPLACE INTO bans(user_id,reason,created_at) VALUES(?,?,?)').run(target.id,String(req.body.reason||'Moderação'),now());
  res.json({ok:true});
});

app.post('/admin/unban', auth, ownerOnly, (req,res) => {
  const target = db.prepare('SELECT id FROM users WHERE lower(username)=lower(?)').get(String(req.body.username||''));
  if (!target) return res.status(404).json({error:'Usuário não encontrado.'});
  db.prepare('DELETE FROM bans WHERE user_id=?').run(target.id); res.json({ok:true});
});

app.post('/admin/role', auth, ownerOnly, (req,res) => {
  const target = db.prepare('SELECT * FROM users WHERE lower(username)=lower(?)').get(String(req.body.username||''));
  const role = String(req.body.role||'PLAYER').toUpperCase();
  if (!target) return res.status(404).json({error:'Usuário não encontrado.'});
  if (target.role === 'OWNER') return res.status(403).json({error:'O dono não pode perder OWNER.'});
  if (!['PLAYER','ADMIN','MODERATOR'].includes(role)) return res.status(400).json({error:'Cargo inválido.'});
  db.prepare('UPDATE users SET role=? WHERE id=?').run(role,target.id); res.json({ok:true,role});
});

app.listen(port, () => console.log(`XOLBOR backend on http://localhost:${port}`));
