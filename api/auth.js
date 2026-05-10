// ============================================================
// Vercel Serverless Function — /api/auth
// CommonJS — Vercel Blob with PRIVATE store access
// ============================================================
const { put, head, getDownloadUrl } = require('@vercel/blob');
const crypto = require('crypto');

const BLOB_KEY  = 'qa-system/users.json';
const TOKEN_TTL = 8 * 60 * 60 * 1000;
const SALT      = process.env.AUTH_SALT || 'qa_salt_v1_2026';

function hashPwd(p) { return crypto.createHash('sha256').update(p + SALT).digest('hex'); }
function mkToken()  { return crypto.randomBytes(32).toString('hex'); }

// ── Read users — private store uses token-authenticated fetch ──
async function readUsers() {
  try {
    const blobToken = process.env.BLOB_READ_WRITE_TOKEN;
    // head() returns metadata including url for private blobs
    const info = await head(BLOB_KEY, { token: blobToken }).catch(() => null);
    if (!info) return [];
    // For private blobs, fetch with Authorization header
    const r = await fetch(info.url, {
      headers: { Authorization: `Bearer ${blobToken}` },
    });
    if (!r.ok) return [];
    return await r.json();
  } catch (e) {
    console.error('readUsers error:', e.message);
    return [];
  }
}

// ── Write users — private store ──
async function writeUsers(users) {
  const blobToken = process.env.BLOB_READ_WRITE_TOKEN;
  await put(BLOB_KEY, JSON.stringify(users, null, 2), {
    access: 'private',
    contentType: 'application/json',
    addRandomSuffix: false,
    token: blobToken,
  });
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,x-auth-token');
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action || (req.body && req.body.action) || '';
  const body   = req.body || {};

  try {
    if (action === 'register') return await doRegister(body, res);
    if (action === 'login')    return await doLogin(body, res);
    if (action === 'verify')   return await doVerify(req, res);
    if (action === 'logout')   return await doLogout(req, body, res);
    if (action === 'list')     return await doList(req, res);
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (e) {
    console.error('[auth]', e);
    return res.status(500).json({ error: 'Server error: ' + e.message });
  }
};

async function doRegister({ name, email, password }, res) {
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email and password are required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Invalid email address' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const users   = await readUsers();
  const emailLC = email.toLowerCase().trim();
  if (users.find(u => u.email === emailLC))
    return res.status(409).json({ error: 'Email already registered' });

  const tok     = mkToken();
  const isFirst = users.length === 0;
  users.push({
    id:          crypto.randomUUID(),
    name:        name.trim(),
    email:       emailLC,
    password:    hashPwd(password),
    role:        isFirst ? 'admin' : 'member',
    createdAt:   new Date().toISOString(),
    lastLogin:   new Date().toISOString(),
    token:       tok,
    tokenExpiry: Date.now() + TOKEN_TTL,
    active:      true,
  });
  await writeUsers(users);
  return res.status(201).json({
    ok: true, token: tok,
    name: name.trim(), email: emailLC,
    role: isFirst ? 'admin' : 'member',
  });
}

async function doLogin({ email, password }, res) {
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

  const users   = await readUsers();
  const emailLC = email.toLowerCase().trim();
  const idx     = users.findIndex(u => u.email === emailLC);

  if (idx === -1)         return res.status(401).json({ error: 'Email not found' });
  if (!users[idx].active) return res.status(403).json({ error: 'Account is deactivated' });
  if (users[idx].password !== hashPwd(password))
    return res.status(401).json({ error: 'Incorrect password' });

  users[idx].token       = mkToken();
  users[idx].tokenExpiry = Date.now() + TOKEN_TTL;
  users[idx].lastLogin   = new Date().toISOString();
  await writeUsers(users);

  return res.status(200).json({
    ok: true,
    token:  users[idx].token,
    name:   users[idx].name,
    email:  emailLC,
    role:   users[idx].role,
  });
}

async function doVerify(req, res) {
  const tok = req.headers['x-auth-token'] || req.query.token || '';
  if (!tok) return res.status(200).json({ valid: false });

  const users = await readUsers();
  const idx   = users.findIndex(u => u.token === tok);

  if (idx === -1)                          return res.status(200).json({ valid: false, reason: 'invalid' });
  if (Date.now() > users[idx].tokenExpiry) return res.status(200).json({ valid: false, reason: 'expired' });

  users[idx].tokenExpiry = Date.now() + TOKEN_TTL;
  await writeUsers(users);

  return res.status(200).json({
    valid: true,
    name:  users[idx].name,
    email: users[idx].email,
    role:  users[idx].role,
  });
}

async function doLogout(req, body, res) {
  const tok = req.headers['x-auth-token'] || body.token || '';
  if (!tok) return res.status(200).json({ ok: true });

  const users = await readUsers();
  const idx   = users.findIndex(u => u.token === tok);
  if (idx !== -1) {
    users[idx].token       = '';
    users[idx].tokenExpiry = 0;
    await writeUsers(users);
  }
  return res.status(200).json({ ok: true });
}

async function doList(req, res) {
  const tok    = req.headers['x-auth-token'] || req.query.token || '';
  const users  = await readUsers();
  const caller = users.find(u => u.token === tok && Date.now() < u.tokenExpiry);
  if (!caller || caller.role !== 'admin')
    return res.status(403).json({ error: 'Admin only' });

  return res.status(200).json({
    users: users.map(u => ({
      id: u.id, name: u.name, email: u.email,
      role: u.role, active: u.active,
      createdAt: u.createdAt, lastLogin: u.lastLogin,
    }))
  });
}
