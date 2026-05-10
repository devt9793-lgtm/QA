// ============================================================
// Vercel Serverless Function — /api/auth
// Handles: register, login, verify, logout
// Storage:  Vercel Blob (users.json — passwords hashed SHA-256)
// ============================================================
import { put, head } from '@vercel/blob';
import crypto from 'crypto';

const BLOB_KEY  = 'qa-system/users.json';
const TOKEN_TTL = 8 * 60 * 60 * 1000; // 8 hours ms
const SALT      = process.env.AUTH_SALT || 'qa_salt_v1_2026';

// ─── helpers ──────────────────────────────────────────────────
function hashPwd(p)  { return crypto.createHash('sha256').update(p + SALT).digest('hex'); }
function mkToken()   { return crypto.randomBytes(32).toString('hex'); }
function ok(res, d)  { return res.status(200).json(d); }
function err(res, s, m) { return res.status(s).json({ error: m }); }

// ─── Blob read/write ──────────────────────────────────────────
async function readUsers() {
  try {
    const info = await head(BLOB_KEY, { token: process.env.BLOB_READ_WRITE_TOKEN }).catch(() => null);
    if (!info) return [];
    const r = await fetch(info.downloadUrl);
    return r.ok ? await r.json() : [];
  } catch { return []; }
}

async function writeUsers(users) {
  await put(BLOB_KEY, JSON.stringify(users, null, 2), {
    access: 'public',
    contentType: 'application/json',
    addRandomSuffix: false,
    token: process.env.BLOB_READ_WRITE_TOKEN,
  });
}

// ─── CORS ─────────────────────────────────────────────────────
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,x-auth-token');
}

// ─── Main handler ─────────────────────────────────────────────
export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action || req.body?.action || '';
  const body   = req.body || {};

  try {
    if (action === 'register') return await doRegister(body, res);
    if (action === 'login')    return await doLogin(body, res);
    if (action === 'verify')   return await doVerify(req, res);
    if (action === 'logout')   return await doLogout(req, body, res);
    if (action === 'list')     return await doList(req, res);      // admin only
    return err(res, 400, 'Unknown action');
  } catch (e) {
    console.error('[auth]', e);
    return err(res, 500, 'Server error: ' + e.message);
  }
}

// ─── REGISTER ────────────────────────────────────────────────
async function doRegister({ name, email, password }, res) {
  if (!name || !email || !password) return err(res, 400, 'Name, email and password are required');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err(res, 400, 'Invalid email address');
  if (password.length < 6) return err(res, 400, 'Password must be at least 6 characters');

  const users   = await readUsers();
  const emailLC = email.toLowerCase().trim();
  if (users.find(u => u.email === emailLC)) return err(res, 409, 'Email already registered');

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
  return ok(res, { ok: true, token: tok, name: name.trim(), email: emailLC, role: isFirst ? 'admin' : 'member' });
}

// ─── LOGIN ────────────────────────────────────────────────────
async function doLogin({ email, password }, res) {
  if (!email || !password) return err(res, 400, 'Email and password are required');
  const users   = await readUsers();
  const emailLC = email.toLowerCase().trim();
  const idx     = users.findIndex(u => u.email === emailLC);
  if (idx === -1)             return err(res, 401, 'Email not found');
  if (!users[idx].active)     return err(res, 403, 'Account is deactivated');
  if (users[idx].password !== hashPwd(password)) return err(res, 401, 'Incorrect password');

  users[idx].token       = mkToken();
  users[idx].tokenExpiry = Date.now() + TOKEN_TTL;
  users[idx].lastLogin   = new Date().toISOString();
  await writeUsers(users);
  return ok(res, { ok: true, token: users[idx].token, name: users[idx].name, email: emailLC, role: users[idx].role });
}

// ─── VERIFY ───────────────────────────────────────────────────
async function doVerify(req, res) {
  const tok   = req.headers['x-auth-token'] || req.query.token || '';
  if (!tok) return ok(res, { valid: false });
  const users = await readUsers();
  const idx   = users.findIndex(u => u.token === tok);
  if (idx === -1)                       return ok(res, { valid: false, reason: 'invalid' });
  if (Date.now() > users[idx].tokenExpiry) return ok(res, { valid: false, reason: 'expired' });
  users[idx].tokenExpiry = Date.now() + TOKEN_TTL; // refresh
  await writeUsers(users);
  return ok(res, { valid: true, name: users[idx].name, email: users[idx].email, role: users[idx].role });
}

// ─── LOGOUT ───────────────────────────────────────────────────
async function doLogout(req, body, res) {
  const tok   = req.headers['x-auth-token'] || body.token || '';
  if (!tok) return ok(res, { ok: true });
  const users = await readUsers();
  const idx   = users.findIndex(u => u.token === tok);
  if (idx !== -1) { users[idx].token = ''; users[idx].tokenExpiry = 0; await writeUsers(users); }
  return ok(res, { ok: true });
}

// ─── LIST USERS (admin only) ──────────────────────────────────
async function doList(req, res) {
  const tok   = req.headers['x-auth-token'] || req.query.token || '';
  const users = await readUsers();
  const caller = users.find(u => u.token === tok && Date.now() < u.tokenExpiry);
  if (!caller || caller.role !== 'admin') return err(res, 403, 'Admin only');
  return ok(res, {
    users: users.map(u => ({
      id: u.id, name: u.name, email: u.email,
      role: u.role, active: u.active,
      createdAt: u.createdAt, lastLogin: u.lastLogin,
    }))
  });
}
