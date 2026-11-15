// back/index.js
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { z } from 'zod';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import sgMail from '@sendgrid/mail';
import multer from 'multer';
import { parse } from 'csv-parse';
import fs from 'fs';
import Stripe from 'stripe';

dotenv.config();
const { Pool } = pg;
const app = express();
app.set('trust proxy', 1);

app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, contentSecurityPolicy: false }));

const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:5173').split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    console.warn('CORS bloqueado para origen:', origin);
    cb(new Error('Origen no permitido por CORS'));
  },
  credentials: true,
}));

// Middleware de JSON que respeta el webhook de Stripe (raw body)
app.use((req, res, next) => {
  if (req.originalUrl === '/api/webhooks/stripe') return next();
  express.json({ limit: '1mb' })(req, res, next);
});
app.use(cookieParser());

// ---------- VALIDACIÓN DE VARIABLES DE ENTORNO ----------
const envSchema = z.object({
  PORT: z.string().default('3000'),
  DATABASE_URL: z.string().url().optional(),
  PGUSER: z.string().optional(),
  PGHOST: z.string().optional(),
  PGDATABASE: z.string().optional(),
  PGPASSWORD: z.string().optional(),
  PGPORT: z.string().default('5432'),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET debe tener al menos 32 caracteres'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET debe tener al menos 32 caracteres'),
  CORS_ORIGINS: z.string().min(1, 'CORS_ORIGINS es obligatorio'),
  FRONTEND_URL: z.string().url('FRONTEND_URL debe ser una URL válida'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
}).refine(
  (data) => data.DATABASE_URL || (data.PGUSER && data.PGHOST && data.PGDATABASE && data.PGPASSWORD),
  { message: 'Debes configurar DATABASE_URL o las variables PGUSER/PGHOST/PGDATABASE/PGPASSWORD' }
);

// ---------- RATE LIMITING ----------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos. Prueba de nuevo en 15 minutos.' },
});

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas peticiones. Espera unos minutos.' },
  skip: (req) => req.path === '/health',
});
app.use(globalLimiter);

// ---------- POSTGRESQL ----------
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
      }
    : {
        user: process.env.PGUSER,
        host: process.env.PGHOST,
        database: process.env.PGDATABASE,
        password: process.env.PGPASSWORD,
        port: process.env.PGPORT,
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
      }
);
// ---------- JWT ----------
const ACCESS_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_TTL = '15m';
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const COOKIE_NAME = 'refresh_token';
const COOKIE_OPTS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: '/api/auth',
  maxAge: REFRESH_TTL_MS,
};

function log(level, msg, extra = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...extra }));
}
function signAccess(user) {
  return jwt.sign(
    { id: user.id, restaurantId: user.restaurant_id, role: user.role, email: user.email, name: user.full_name },
    ACCESS_SECRET,
    { expiresIn: ACCESS_TTL }
  );
}
function signRefresh(user) {
  return jwt.sign({ id: user.id, type: 'refresh' }, REFRESH_SECRET, { expiresIn: '7d' });
}

// ---------- EMAIL ----------
let mailer = null;
let mailerType = 'none';

if (process.env.EMAIL_ENABLED === 'true' && process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  mailerType = 'sendgrid';
  log('info', 'SendGrid configurado');
} else if (process.env.EMAIL_ENABLED === 'true' && process.env.SMTP_HOST) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  mailerType = 'smtp';
  log('info', 'SMTP configurado');
} else {
  log('warn', 'EMAIL_ENABLED=false — los emails se imprimirán en consola');
}

async function sendMail({ to, subject, html, text }) {
  if (mailerType === 'sendgrid') {
    try {
      await sgMail.send({
        to,
        from: { email: process.env.SENDGRID_FROM_EMAIL, name: process.env.SENDGRID_FROM_NAME },
        subject,
        html: html || text,
        text: text || undefined,
      });
      log('info', 'EMAIL enviado (SendGrid)', { to, subject });
    } catch (e) {
      log('error', 'EMAIL fallo (SendGrid)', { error: e.message });
    }
  } else if (mailerType === 'smtp') {
    try {
      await mailer.sendMail({ from: process.env.EMAIL_FROM, to, subject, html, text });
      log('info', 'EMAIL enviado (SMTP)', { to, subject });
    } catch (e) {
      log('error', 'EMAIL fallo (SMTP)', { error: e.message });
    }
  } else {
    log('info', 'EMAIL (modo consola)', { to, subject, text });
  }
}

// ---------- MIDDLEWARES ----------
async function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Token requerido' });
  try {
    const payload = jwt.verify(h.replace('Bearer ', ''), ACCESS_SECRET);
    const { rows } = await pool.query('SELECT id, restaurant_id, role, active FROM users WHERE id=$1', [payload.id]);
    if (!rows[0] || !rows[0].active) return res.status(401).json({ error: 'Sesión no válida' });
    req.user = { id: rows[0].id, restaurantId: rows[0].restaurant_id, role: rows[0].role };
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Sin permisos' });
    next();
  };
}
async function audit(client, rid, uid, action, entity, entityId, metadata = {}) {
  try {
    await client.query(
      `INSERT INTO audit_logs (restaurant_id, user_id, action, entity, entity_id, metadata)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [rid, uid, action, entity, entityId, metadata]
    );
  } catch (e) { log('warn', 'audit fallo', { error: e.message }); }
}
async function syncStock(client, productId) {
  const r = await client.query(
    'SELECT COALESCE(SUM(quantity_remaining),0) AS total FROM product_batches WHERE product_id=$1',
    [productId]);
  await client.query('UPDATE products SET stock_current=$1 WHERE id=$2', [r.rows[0].total, productId]);
  return Number(r.rows[0].total);
}
async function requireSubscription(req, res, next) {
  if (req.user.role === 'superadmin') return next();
  const { rows } = await pool.query('SELECT subscription_status FROM restaurants WHERE id=$1', [req.user.restaurantId]);
  const status = rows[0]?.subscription_status;
  if (!['trial', 'active'].includes(status))
    return res.status(402).json({ error: 'Suscripción inactiva. Contacta con soporte.' });
  next();
}

// ---------- AUTH ----------
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  log('info', 'LOGIN intento', { body: { email: req.body?.email, passwordLen: req.body?.password?.length } });
  const parsed = z.object({ email: z.string().email(), password: z.string().min(6) }).safeParse(req.body);
  if (!parsed.success) {
    log('warn', 'LOGIN zod fallo', { errors: parsed.error.errors });
    return res.status(400).json({ error: 'Datos de login inválidos' });
  }
  const { email, password } = parsed.data;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    log('info', 'LOGIN query users', { found: rows.length, email });
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
    if (!user.active) return res.status(401).json({ error: 'Credenciales inválidas' });
    const ok = await bcrypt.compare(password, user.password_hash);
    log('info', 'LOGIN bcrypt.compare', { email, coincide: ok });
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });

    const isFirstLogin = user.last_login_at == null;
    await pool.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);

    let companyName = null;
    if (user.restaurant_id) {
      const r = await pool.query('SELECT name FROM restaurants WHERE id=$1', [user.restaurant_id]);
      companyName = r.rows[0]?.name || null;
    }

    const access = signAccess(user);
    const refresh = signRefresh(user);
    res.cookie(COOKIE_NAME, refresh, COOKIE_OPTS);
    log('info', 'LOGIN OK', { userId: user.id, role: user.role, email: user.email, firstLogin: isFirstLogin });
    res.json({
      token: access,
      user: {
        id: user.id, name: user.full_name, role: user.role, email: user.email,
        restaurantId: user.restaurant_id, companyName,
      },
      firstLogin: isFirstLogin,
    });
  } catch (err) {
    log('error', 'LOGIN excepción', { error: err.message });
    res.status(500).json({ error: 'Error interno en login' });
  }
});

app.post('/api/auth/refresh', async (req, res) => {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Sin refresh token' });
  try {
    const payload = jwt.verify(token, REFRESH_SECRET);
    if (payload.type !== 'refresh') throw new Error('Tipo inválido');
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1 AND active=true', [payload.id]);
    if (!rows[0]) throw new Error('Usuario no válido');
    const user = rows[0];
    let companyName = null;
    if (user.restaurant_id) {
      const r = await pool.query('SELECT name FROM restaurants WHERE id=$1', [user.restaurant_id]);
      companyName = r.rows[0]?.name || null;
    }
    const access = signAccess(user);
    res.json({
      token: access,
      user: {
        id: user.id, name: user.full_name, role: user.role, email: user.email,
        restaurantId: user.restaurant_id, companyName,
      },
    });
  } catch {
    res.clearCookie(COOKIE_NAME, { ...COOKIE_OPTS, maxAge: undefined });
    res.status(401).json({ error: 'Refresh inválido' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { ...COOKIE_OPTS, maxAge: undefined });
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

// ---------- REGISTRO CON INVITACIÓN ----------
app.post('/api/auth/register', async (req, res) => {
  const { email, password, full_name, invite_code, company_name } = req.body;
  if (!email || !password || !full_name || !invite_code)
    return res.status(400).json({ error: 'Email, contraseña, nombre y código son obligatorios' });
  if (password.length < 8) return res.status(400).json({ error: 'Contraseña mínimo 8 caracteres' });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    return res.status(400).json({ error: 'Email inválido' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const invite = await client.query(
      `SELECT * FROM invite_codes WHERE code=$1 AND used=false AND expires_at > NOW() FOR UPDATE`,
      [invite_code.trim().toUpperCase()]);
    if (!invite.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Código inválido, usado o expirado' });
    }
    const exists = await client.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Ya existe un usuario con ese email' });
    }
    let restaurantId = invite.rows[0].restaurant_id;
    let restaurantName = null;
    if (!restaurantId) {
      restaurantName = company_name || `Empresa de ${full_name}`;
      const r = await client.query(
        'INSERT INTO restaurants (name, plan, industry, subscription_status) VALUES ($1,$2,$3,$4) RETURNING id',
        [restaurantName, 'trial', 'food', 'trial']);
      restaurantId = r.rows[0].id;
      await client.query('INSERT INTO categories (restaurant_id, name) VALUES ($1,$2)', [restaurantId, 'General']);
    } else {
      const r = await client.query('SELECT name FROM restaurants WHERE id=$1', [restaurantId]);
      restaurantName = r.rows[0]?.name || null;
    }
    const hash = await bcrypt.hash(password, 10);
    const user = await client.query(
      `INSERT INTO users (restaurant_id, email, password_hash, full_name, role, active, last_login_at)
       VALUES ($1,$2,$3,$4,$5,true,NOW()) RETURNING id, email, full_name, role, restaurant_id`,
      [restaurantId, email, hash, full_name, invite.rows[0].role]);
    await client.query(
      'UPDATE invite_codes SET used=true, used_by=$1, used_at=NOW() WHERE id=$2',
      [user.rows[0].id, invite.rows[0].id]);
    await client.query('COMMIT');
    const access = jwt.sign(
      { id: user.rows[0].id, restaurantId: user.rows[0].restaurant_id, role: user.rows[0].role, email: user.rows[0].email, name: user.rows[0].full_name },
      ACCESS_SECRET, { expiresIn: '8h' });
    const refresh = jwt.sign({ id: user.rows[0].id, type: 'refresh' }, REFRESH_SECRET, { expiresIn: '7d' });
    res.cookie(COOKIE_NAME, refresh, COOKIE_OPTS);
    log('info', 'registro ok', { email, role: user.rows[0].role, restaurantId });
    res.status(201).json({
      token: access,
      user: {
        id: user.rows[0].id, name: user.rows[0].full_name, role: user.rows[0].role,
        email: user.rows[0].email, restaurantId: user.rows[0].restaurant_id,
        companyName: restaurantName,
      },
      firstLogin: true,
    });
  } catch (e) {
    await client.query('ROLLBACK');
    log('error', 'registro fallo', { error: e.message });
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

// ---------- RECUPERACIÓN DE CONTRASEÑA ----------
app.post('/api/auth/forgot-password', loginLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requerido' });
  try {
    const { rows } = await pool.query('SELECT id, email, full_name FROM users WHERE email=$1 AND active=true', [email]);
    if (rows[0]) {
      const token = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      await pool.query(
        'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1,$2,$3)',
        [rows[0].id, tokenHash, expiresAt]);
      const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
      await sendMail({
        to: rows[0].email,
        subject: 'Recupera tu contraseña de StockFlow',
        text: `Hola ${rows[0].full_name},\n\nPara restablecer tu contraseña, abre este enlace (válido 1 hora):\n${link}\n\nSi no fuiste tú, ignora este mensaje.`,
        html: `<p>Hola ${rows[0].full_name},</p><p>Para restablecer tu contraseña, haz clic aquí (válido 1 hora):</p><p><a href="${link}">${link}</a></p><p>Si no fuiste tú, ignora este mensaje.</p>`,
      });
    }
    res.json({ ok: true, message: 'Si el email existe, recibirás un enlace de recuperación.' });
  } catch (e) {
    log('error', 'forgot-password fallo', { error: e.message });
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password || password.length < 8)
    return res.status(400).json({ error: 'Token y contraseña (mín. 8) son obligatorios' });
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const { rows } = await pool.query(
      `SELECT id, user_id FROM password_reset_tokens
       WHERE token_hash=$1 AND used=false AND expires_at > NOW()`, [tokenHash]);
    if (!rows[0]) return res.status(400).json({ error: 'Token inválido o expirado' });
    const hash = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, rows[0].user_id]);
    await pool.query('UPDATE password_reset_tokens SET used=true WHERE id=$1', [rows[0].id]);
    res.json({ ok: true });
  } catch (e) {
    log('error', 'reset-password fallo', { error: e.message });
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/auth/welcome-seen', auth, async (req, res) => {
  try {
    await pool.query('UPDATE users SET welcome_seen = true WHERE id = $1', [req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error interno' });
  }
});

// ---------- INVITACIONES (superadmin) ----------
app.post('/api/admin/invites', auth, requireRole('superadmin'), async (req, res) => {
  const { role = 'admin', restaurant_id = null, expires_hours = 72 } = req.body;
  if (!['admin','manager','warehouse','kitchen'].includes(role))
    return res.status(400).json({ error: 'Rol inválido' });
  try {
    const code = crypto.randomBytes(6).toString('hex').toUpperCase();
    const expiresAt = new Date(Date.now() + Number(expires_hours) * 60 * 60 * 1000);
    const { rows } = await pool.query(
      `INSERT INTO invite_codes (code, role, restaurant_id, expires_at, created_by)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [code, role, restaurant_id || null, expiresAt, req.user.id]);
    log('info', 'invite generado', { code, role });
    res.status(201).json(rows[0]);
  } catch (e) {
    log('error', 'invite fallo', { error: e.message });
    res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/api/admin/invites', auth, requireRole('superadmin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT i.*, r.name AS restaurant_name, u.full_name AS used_by_name
     FROM invite_codes i
     LEFT JOIN restaurants r ON r.id=i.restaurant_id
     LEFT JOIN users u ON u.id=i.used_by
     ORDER BY i.created_at DESC LIMIT 100`);
  res.json(rows);
});

// ---------- DASHBOARD ----------
app.get('/api/dashboard', auth, requireSubscription, async (req, res) => {
  const rid = req.user.restaurantId;
  const q = (sql, p = []) => pool.query(sql, [rid, ...p]);
  const [inv, low, out, exp, purch, waste] = await Promise.all([
    q('SELECT COALESCE(SUM(stock_current * purchase_price),0) AS total, COUNT(*) AS count FROM products WHERE restaurant_id=$1 AND active=true'),
    q('SELECT COUNT(*) FROM products WHERE restaurant_id=$1 AND active=true AND stock_current > 0 AND stock_current <= stock_min'),
    q('SELECT COUNT(*) FROM products WHERE restaurant_id=$1 AND active=true AND stock_current = 0'),
    q("SELECT COUNT(*) FROM product_batches WHERE restaurant_id=$1 AND quantity_remaining > 0 AND expiration_date IS NOT NULL AND expiration_date <= CURRENT_DATE + 7"),
    q("SELECT COALESCE(SUM(ABS(quantity) * p.purchase_price),0) AS total FROM stock_movements m JOIN products p ON p.id=m.product_id WHERE m.restaurant_id=$1 AND m.type='entrada' AND m.movement_date >= date_trunc('month', CURRENT_DATE)"),
    q("SELECT COALESCE(SUM(ABS(quantity) * p.purchase_price),0) AS total FROM stock_movements m JOIN products p ON p.id=m.product_id WHERE m.restaurant_id=$1 AND m.type='salida' AND m.reason IN ('waste','expired','breakage') AND m.movement_date >= date_trunc('month', CURRENT_DATE)"),
  ]);
  res.json({
    inventoryValue: Number(inv.rows[0].total), productCount: Number(inv.rows[0].count),
    lowStock: Number(low.rows[0].count), outOfStock: Number(out.rows[0].count),
    expiringSoon: Number(exp.rows[0].count), purchasesMonth: Number(purch.rows[0].total),
    wasteMonth: Number(waste.rows[0].total),
  });
});

// ---------- USUARIOS ----------
app.get('/api/users', auth, requireSubscription, requireRole('admin','manager','superadmin'), async (req, res) => {
  const rid = req.user.role === 'superadmin' ? null : req.user.restaurantId;
  const sql = rid
    ? `SELECT u.id, u.email, u.full_name, u.role, u.active, u.restaurant_id, r.name AS restaurant_name
       FROM users u LEFT JOIN restaurants r ON r.id=u.restaurant_id WHERE u.restaurant_id=$1 ORDER BY u.full_name`
    : `SELECT u.id, u.email, u.full_name, u.role, u.active, u.restaurant_id, r.name AS restaurant_name
       FROM users u LEFT JOIN restaurants r ON r.id=u.restaurant_id ORDER BY u.full_name`;
  const { rows } = await pool.query(sql, rid ? [rid] : []);
  res.json(rows);
});

app.post('/api/users', auth, requireSubscription, requireRole('admin','superadmin'), async (req, res) => {
  const { email, password, full_name, role, restaurant_id } = req.body;
  if (!email || !password || !full_name || !role)
    return res.status(400).json({ error: 'Email, contraseña, nombre y rol son obligatorios' });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Email inválido' });
  if (password.length < 8) return res.status(400).json({ error: 'Contraseña mínimo 8 caracteres' });
  const targetRid = req.user.role === 'superadmin' ? (restaurant_id || null) : req.user.restaurantId;
  if (req.user.role === 'superadmin' && role !== 'superadmin' && !targetRid)
    return res.status(400).json({ error: 'Debes asignar un restaurante al usuario' });
  if (req.user.role !== 'superadmin' && role === 'superadmin')
    return res.status(403).json({ error: 'Solo el superadmin puede crear superadmins' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const exists = await client.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows[0]) throw new Error('Ya existe un usuario con ese email');
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await client.query(
      `INSERT INTO users (restaurant_id, email, password_hash, full_name, role, last_login_at)
       VALUES ($1,$2,$3,$4,$5,NOW()) RETURNING id, email, full_name, role, active, restaurant_id`,
      [targetRid, email, hash, full_name, role]);
    if (targetRid) await audit(client, targetRid, req.user.id, 'user.created', 'user', rows[0].id, { email, role });
    await client.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

app.put('/api/users/:id', auth, requireSubscription, requireRole('admin','superadmin'), async (req, res) => {
  const { full_name, role, active } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const target = await client.query('SELECT * FROM users WHERE id=$1', [req.params.id]);
    if (!target.rows[0]) throw new Error('Usuario no encontrado');
    if (req.user.role !== 'superadmin' && target.rows[0].restaurant_id !== req.user.restaurantId)
      throw new Error('Sin permisos sobre este usuario');
    if (role === 'superadmin' && req.user.role !== 'superadmin')
      throw new Error('Solo el superadmin puede asignar ese rol');
    const { rows } = await client.query(
      `UPDATE users SET full_name=COALESCE($1, full_name), role=COALESCE($2, role), active=COALESCE($3, active)
       WHERE id=$4 RETURNING id, email, full_name, role, active, restaurant_id`,
      [full_name ?? null, role ?? null, active ?? null, req.params.id]);
    if (target.rows[0].restaurant_id)
      await audit(client, target.rows[0].restaurant_id, req.user.id, 'user.updated', 'user', req.params.id, { role, active });
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

app.delete('/api/users/:id', auth, requireSubscription, requireRole('admin','superadmin'), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const target = await client.query('SELECT * FROM users WHERE id=$1', [req.params.id]);
    if (!target.rows[0]) throw new Error('Usuario no encontrado');
    if (target.rows[0].id === req.user.id) throw new Error('No puedes desactivar tu propio usuario');
    if (req.user.role !== 'superadmin' && target.rows[0].restaurant_id !== req.user.restaurantId)
      throw new Error('Sin permisos sobre este usuario');
    await client.query('UPDATE users SET active=false WHERE id=$1', [req.params.id]);
    if (target.rows[0].restaurant_id)
      await audit(client, target.rows[0].restaurant_id, req.user.id, 'user.deactivated', 'user', req.params.id, {});
    await client.query('COMMIT');
    res.status(204).end();
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

app.post('/api/users/:id/reset-password', auth, requireSubscription, requireRole('admin','superadmin'), async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Contraseña mínimo 8 caracteres' });
  const client = await pool.connect();
  try {
    const target = await client.query('SELECT * FROM users WHERE id=$1', [req.params.id]);
    if (!target.rows[0]) throw new Error('Usuario no encontrado');
    if (req.user.role !== 'superadmin' && target.rows[0].restaurant_id !== req.user.restaurantId)
      throw new Error('Sin permisos sobre este usuario');
    const hash = await bcrypt.hash(password, 10);
    await client.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

// ---------- MI EMPRESA ----------
app.get('/api/my-restaurant', auth, async (req, res) => {
  if (!req.user.restaurantId) return res.status(404).json({ error: 'Sin empresa asignada' });
  const { rows } = await pool.query(
    'SELECT id, name, plan, industry, subscription_status, active FROM restaurants WHERE id=$1',
    [req.user.restaurantId]);
  if (!rows[0]) return res.status(404).json({ error: 'Empresa no encontrada' });
  res.json(rows[0]);
});

// ---------- RESTAURANTES ----------
app.get('/api/restaurants', auth, requireRole('superadmin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT r.*, COUNT(u.id) FILTER (WHERE u.active=true) AS user_count
     FROM restaurants r LEFT JOIN users u ON u.restaurant_id=r.id
     GROUP BY r.id ORDER BY r.created_at DESC`);
  res.json(rows);
});

app.post('/api/restaurants', auth, requireRole('superadmin'), async (req, res) => {
  const { name, plan, industry } = req.body;
  if (!name) return res.status(400).json({ error: 'El nombre es obligatorio' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      'INSERT INTO restaurants (name, plan, industry, subscription_status) VALUES ($1,$2,$3,$4) RETURNING *',
      [name, plan || 'basic', industry || 'food', 'trial']);
    await client.query('INSERT INTO categories (restaurant_id, name) VALUES ($1,$2)', [rows[0].id, 'General']);
    await client.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

app.put('/api/restaurants/:id', auth, requireRole('superadmin'), async (req, res) => {
  const { name, plan, active, industry, subscription_status } = req.body;
  const { rows } = await pool.query(
    `UPDATE restaurants SET name=COALESCE($1,name), plan=COALESCE($2,plan), active=COALESCE($3,active),
       industry=COALESCE($4,industry), subscription_status=COALESCE($5,subscription_status)
     WHERE id=$6 RETURNING *`,
    [name ?? null, plan ?? null, active ?? null, industry ?? null, subscription_status ?? null, req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Restaurante no encontrado' });
  res.json(rows[0]);
});

// ---------- PRODUCTOS ----------
app.get('/api/products', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT p.*, c.name AS category_name, s.company_name AS supplier_name
     FROM products p LEFT JOIN categories c ON c.id=p.category_id
     LEFT JOIN suppliers s ON s.id=p.supplier_id
     WHERE p.restaurant_id=$1 AND p.active=true ORDER BY p.name`, [req.user.restaurantId]);
  res.json(rows);
});

app.post('/api/products', auth, requireSubscription, requireRole('admin','manager','warehouse'), async (req, res) => {
  const parsed = z.object({
    name: z.string().min(1).max(200),
    sku: z.string().max(100).optional().nullable(),
    barcode: z.string().max(100).optional().nullable(),
    description: z.string().optional().nullable(),
    unit: z.string().max(20),
    purchase_price: z.number().nonnegative().default(0),
    stock_min: z.number().nonnegative().default(0),
    category_id: z.number().int().positive().optional().nullable(),
    supplier_id: z.number().int().positive().optional().nullable(),
    location: z.string().max(100).optional().nullable(),
    image_url: z.string().url().optional().nullable(),
    custom_attributes: z.record(z.any()).optional(),
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Datos de producto inválidos', detalle: parsed.error.errors });
  const d = parsed.data;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO products (restaurant_id, category_id, supplier_id, name, sku, barcode, description, unit, purchase_price, stock_min, location, image_url, custom_attributes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [req.user.restaurantId, d.category_id||null, d.supplier_id||null, d.name, d.sku, d.barcode, d.description, d.unit, d.purchase_price, d.stock_min, d.location, d.image_url, d.custom_attributes||{}]);
    await audit(client, req.user.restaurantId, req.user.id, 'product.created', 'product', rows[0].id, { name: d.name });
    await client.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

app.put('/api/products/:id', auth, requireSubscription, requireRole('admin','manager','warehouse'), async (req, res) => {
  const parsed = z.object({
    name: z.string().min(1).max(200),
    sku: z.string().max(100).optional().nullable(),
    barcode: z.string().max(100).optional().nullable(),
    description: z.string().optional().nullable(),
    unit: z.string().max(20),
    purchase_price: z.number().nonnegative(),
    stock_min: z.number().nonnegative(),
    category_id: z.number().int().positive().optional().nullable(),
    supplier_id: z.number().int().positive().optional().nullable(),
    location: z.string().max(100).optional().nullable(),
    image_url: z.string().url().optional().nullable(),
    custom_attributes: z.record(z.any()).optional(),
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Datos de producto inválidos', detalle: parsed.error.errors });
  const d = parsed.data;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE products SET name=$1, sku=$2, barcode=$3, description=$4, unit=$5, purchase_price=$6, stock_min=$7,
         category_id=$8, supplier_id=$9, location=$10, image_url=$11, custom_attributes=$12
       WHERE id=$13 AND restaurant_id=$14 RETURNING *`,
      [d.name, d.sku, d.barcode, d.description, d.unit, d.purchase_price, d.stock_min,
       d.category_id||null, d.supplier_id||null, d.location, d.image_url, d.custom_attributes||{}, req.params.id, req.user.restaurantId]);
    if (!rows[0]) throw new Error('No encontrado');
    await audit(client, req.user.restaurantId, req.user.id, 'product.updated', 'product', req.params.id, { name: d.name });
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

app.delete('/api/products/:id', auth, requireSubscription, requireRole('admin','manager'), async (req, res) => {
  await pool.query('UPDATE products SET active=false WHERE id=$1 AND restaurant_id=$2', [req.params.id, req.user.restaurantId]);
  res.status(204).end();
});

app.get('/api/products/:id/batches', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM product_batches WHERE product_id=$1 AND restaurant_id=$2 AND quantity_remaining > 0
     ORDER BY expiration_date ASC NULLS LAST, received_date ASC`,
    [req.params.id, req.user.restaurantId]);
  res.json(rows);
});

// ---------- MOVIMIENTOS ----------
app.get('/api/movements', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT m.*, p.name AS product_name, u.full_name AS user_name
     FROM stock_movements m JOIN products p ON p.id=m.product_id
     LEFT JOIN users u ON u.id=m.user_id
     WHERE m.restaurant_id=$1 ORDER BY m.movement_date DESC LIMIT 300`, [req.user.restaurantId]);
  res.json(rows);
});

app.post('/api/movements', auth, requireSubscription, requireRole('admin','manager','warehouse','kitchen'), async (req, res) => {
  const parsed = z.object({
    product_id: z.number().int().positive(),
    type: z.enum(['entrada','salida']),
    quantity: z.number().positive(),
    reason: z.string().min(1).max(50),
    notes: z.string().optional().nullable(),
    expiration_date: z.string().optional().nullable(),
    batch_code: z.string().max(100).optional().nullable(),
    unit_cost: z.number().nonnegative().optional(),
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Datos de movimiento inválidos', detalle: parsed.error.errors });
  const { product_id, type, quantity, reason, notes, expiration_date, batch_code, unit_cost } = parsed.data;
  const rid = req.user.restaurantId;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const prod = await client.query('SELECT * FROM products WHERE id=$1 AND restaurant_id=$2 AND active=true FOR UPDATE', [product_id, rid]);
    if (!prod.rows[0]) throw new Error('Producto no encontrado');
    if (type === 'entrada') {
      const batch = await client.query(
        `INSERT INTO product_batches (restaurant_id, product_id, batch_code, quantity_received, quantity_remaining, unit_cost, expiration_date)
         VALUES ($1,$2,$3,$4,$4,$5,$6) RETURNING *`,
        [rid, product_id, batch_code||null, quantity, unit_cost||prod.rows[0].purchase_price, expiration_date||null]);
      await client.query(
        `INSERT INTO stock_movements (restaurant_id, product_id, batch_id, user_id, type, quantity, reason, notes)
         VALUES ($1,$2,$3,$4,'entrada',$5,$6,$7)`,
        [rid, product_id, batch.rows[0].id, req.user.id, quantity, reason, notes||null]);
      await syncStock(client, product_id);
    } else {
      const lots = await client.query(
        `SELECT * FROM product_batches WHERE product_id=$1 AND restaurant_id=$2 AND quantity_remaining > 0
         ORDER BY expiration_date ASC NULLS LAST, received_date ASC FOR UPDATE`,
        [product_id, rid]);
      const disponible = lots.rows.reduce((s, l) => s + Number(l.quantity_remaining), 0);
      if (disponible < quantity) {
        await client.query('ROLLBACK');
        return res.status(400).json({
          error: `Stock insuficiente. Disponible: ${disponible} ${prod.rows[0].unit}, solicitado: ${quantity} ${prod.rows[0].unit}.`,
          disponible, solicitado: quantity, unidad: prod.rows[0].unit,
        });
      }
      let remaining = quantity;
      for (const lot of lots.rows) {
        if (remaining <= 0) break;
        const take = Math.min(remaining, Number(lot.quantity_remaining));
        await client.query('UPDATE product_batches SET quantity_remaining = quantity_remaining - $1 WHERE id=$2', [take, lot.id]);
        await client.query(
          `INSERT INTO stock_movements (restaurant_id, product_id, batch_id, user_id, type, quantity, reason, notes)
           VALUES ($1,$2,$3,$4,'salida',$5,$6,$7)`,
          [rid, product_id, lot.id, req.user.id, -take, reason, notes||null]);
        remaining -= take;
      }
      await syncStock(client, product_id);
    }
    await audit(client, rid, req.user.id, `movement.${type}`, 'product', product_id, { quantity, reason });
    await client.query('COMMIT');
    res.status(201).json({ ok: true });
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

// ---------- IMPORTACIÓN CSV ----------
const upload = multer({ dest: 'uploads/', limits: { fileSize: 5 * 1024 * 1024 } });

app.post('/api/products/import', auth, requireSubscription, requireRole('admin','manager','warehouse'), upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Archivo CSV requerido' });
  const rid = req.user.restaurantId;
  const results = [];
  const errors = [];
  try {
    const parser = fs.createReadStream(req.file.path).pipe(parse({
      columns: true,
      skip_empty_lines: true,
      bom: true,
      trim: true,
    }));
    for await (const row of parser) {
      const name = (row.name || row.nombre || '').trim();
      if (!name) { errors.push({ row, error: 'Nombre vacío' }); continue; }
      const price = parseFloat(row.purchase_price || row.precio || 0) || 0;
      const stockMin = parseFloat(row.stock_min || row.stock_minimo || 0) || 0;
      try {
        await pool.query(
          `INSERT INTO products (restaurant_id, name, sku, barcode, unit, purchase_price, stock_min, location)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [rid, name, row.sku || null, row.barcode || null, row.unit || 'ud', price, stockMin, row.location || null]);
        results.push({ name, ok: true });
      } catch (e) {
        errors.push({ name, error: e.message });
      }
    }
    fs.unlinkSync(req.file.path);
    res.json({ imported: results.length, errors: errors.length, details: errors.slice(0, 20) });
  } catch (e) {
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(400).json({ error: 'CSV inválido: ' + e.message });
  }
});

// ---------- STRIPE ----------
let stripe = null;
if (process.env.STRIPE_ENABLED === 'true' && process.env.STRIPE_SECRET_KEY) {
  stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
  log('info', 'Stripe configurado');
} else {
  log('warn', 'STRIPE_ENABLED=false — cobros simulados');
}

const PLAN_PRICE = {
  basic: process.env.STRIPE_PRICE_BASIC || null,
  pro: process.env.STRIPE_PRICE_PRO || null,
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE || null,
};

app.post('/api/billing/checkout', auth, requireRole('admin','superadmin'), async (req, res) => {
  const { plan } = req.body;
  if (!['basic','pro','enterprise'].includes(plan))
    return res.status(400).json({ error: 'Plan inválido' });
  const rid = req.user.restaurantId;
  if (!stripe) {
    await pool.query('UPDATE restaurants SET plan=$1, subscription_status=$2 WHERE id=$3', [plan, 'active', rid]);
    return res.json({ simulated: true, message: `Plan ${plan} activado (modo simulado)` });
  }
  try {
    const { rows } = await pool.query('SELECT * FROM restaurants WHERE id=$1', [rid]);
    const restaurant = rows[0];
    let customerId = restaurant.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ name: restaurant.name });
      customerId = customer.id;
      await pool.query('UPDATE restaurants SET stripe_customer_id=$1 WHERE id=$2', [customerId, rid]);
    }
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customerId,
      line_items: [{ price: PLAN_PRICE[plan], quantity: 1 }],
      success_url: `${process.env.FRONTEND_URL}/?billing=success`,
      cancel_url: `${process.env.FRONTEND_URL}/?billing=cancel`,
      metadata: { restaurant_id: String(rid), plan },
    });
    res.json({ url: session.url });
  } catch (e) {
    log('error', 'checkout fallo', { error: e.message });
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) return res.json({ received: true, simulated: true });
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    log('error', 'webhook stripe firma inválida', { error: e.message });
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }
  try {
    if (event.type === 'checkout.session.completed') {
      const s = event.data.object;
      const rid = Number(s.metadata.restaurant_id);
      const plan = s.metadata.plan;
      await pool.query('UPDATE restaurants SET plan=$1, subscription_status=$2 WHERE id=$3', [plan, 'active', rid]);
      log('info', 'stripe checkout ok', { rid, plan });
    } else if (event.type === 'invoice.payment_failed') {
      const inv = event.data.object;
      await pool.query("UPDATE restaurants SET subscription_status='past_due' WHERE stripe_customer_id=$1", [inv.customer]);
    } else if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      await pool.query("UPDATE restaurants SET subscription_status='cancelled' WHERE stripe_customer_id=$1", [sub.customer]);
    }
    res.json({ received: true });
  } catch (e) {
    log('error', 'webhook procesado fallo', { error: e.message });
    res.status(500).json({ error: 'Webhook handler failed' });
  }
});

// ---------- PROVEEDORES ----------
app.get('/api/suppliers', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM suppliers WHERE restaurant_id=$1 ORDER BY company_name', [req.user.restaurantId]);
  res.json(rows);
});
app.post('/api/suppliers', auth, requireSubscription, requireRole('admin','manager'), async (req, res) => {
  const { company_name, contact_name, phone, email, payment_terms } = req.body;
  if (!company_name) return res.status(400).json({ error: 'El nombre de empresa es obligatorio' });
  const { rows } = await pool.query(
    'INSERT INTO suppliers (restaurant_id, company_name, contact_name, phone, email, payment_terms) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [req.user.restaurantId, company_name, contact_name, phone, email, payment_terms]);
  res.status(201).json(rows[0]);
});

// ---------- COMPRAS ----------
app.get('/api/purchases', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT po.*, s.company_name AS supplier_name FROM purchase_orders po
     JOIN suppliers s ON s.id=po.supplier_id WHERE po.restaurant_id=$1 ORDER BY po.created_at DESC`,
    [req.user.restaurantId]);
  res.json(rows);
});
app.get('/api/purchases/suggestions', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT p.id, p.name, p.unit, p.stock_current, p.stock_min,
            s.id AS supplier_id, s.company_name AS supplier_name,
            GREATEST(p.stock_min * 2 - p.stock_current, p.stock_min) AS suggested_qty,
            p.purchase_price
     FROM products p LEFT JOIN suppliers s ON s.id=p.supplier_id
     WHERE p.restaurant_id=$1 AND p.active=true AND p.stock_current <= p.stock_min
     ORDER BY (p.stock_current - p.stock_min) ASC`, [req.user.restaurantId]);
  res.json(rows);
});
app.get('/api/purchases/:id', auth, requireSubscription, async (req, res) => {
  const po = await pool.query('SELECT * FROM purchase_orders WHERE id=$1 AND restaurant_id=$2', [req.params.id, req.user.restaurantId]);
  if (!po.rows[0]) return res.status(404).json({ error: 'Pedido no encontrado' });
  const items = await pool.query(
    `SELECT poi.*, p.name AS product_name FROM purchase_order_items poi
     JOIN products p ON p.id=poi.product_id WHERE poi.purchase_order_id=$1`, [req.params.id]);
  res.json({ ...po.rows[0], items: items.rows });
});
app.post('/api/purchases', auth, requireSubscription, requireRole('admin','manager','warehouse'), async (req, res) => {
  const { supplier_id, items, expected_date, notes } = req.body;
  if (!supplier_id || !Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'Proveedor y al menos una línea son obligatorios' });
  const rid = req.user.restaurantId;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const total = items.reduce((s, i) => s + Number(i.quantity) * Number(i.unit_price), 0);
    const po = await client.query(
      `INSERT INTO purchase_orders (restaurant_id, supplier_id, user_id, status, expected_date, total_amount, notes)
       VALUES ($1,$2,$3,'sent',$4,$5,$6) RETURNING *`,
      [rid, supplier_id, req.user.id, expected_date||null, total, notes||null]);
    for (const it of items) {
      await client.query(
        'INSERT INTO purchase_order_items (purchase_order_id, product_id, quantity, unit_price) VALUES ($1,$2,$3,$4)',
        [po.rows[0].id, it.product_id, it.quantity, it.unit_price]);
    }
    await audit(client, rid, req.user.id, 'purchase.created', 'purchase_order', po.rows[0].id, { total });
    await client.query('COMMIT');
    res.status(201).json(po.rows[0]);
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});
app.post('/api/purchases/:id/receive', auth, requireSubscription, requireRole('admin','manager','warehouse'), async (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'Debes indicar al menos una línea a recibir' });
  const rid = req.user.restaurantId;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const po = await client.query('SELECT * FROM purchase_orders WHERE id=$1 AND restaurant_id=$2 FOR UPDATE', [req.params.id, rid]);
    if (!po.rows[0]) throw new Error('Pedido no encontrado');
    if (po.rows[0].status === 'received') throw new Error('Este pedido ya está recibido por completo');
    for (const it of items) {
      const poi = await client.query('SELECT * FROM purchase_order_items WHERE id=$1 AND purchase_order_id=$2', [it.item_id, req.params.id]);
      if (!poi.rows[0]) throw new Error('Ítem no encontrado');
      const pendiente = Number(poi.rows[0].quantity) - Number(poi.rows[0].received_quantity);
      const qty = Math.min(Number(it.quantity), pendiente);
      if (qty <= 0) continue;
      await client.query('UPDATE purchase_order_items SET received_quantity = received_quantity + $1 WHERE id=$2', [qty, it.item_id]);
      const batch = await client.query(
        `INSERT INTO product_batches (restaurant_id, product_id, batch_code, quantity_received, quantity_remaining, unit_cost, expiration_date)
         VALUES ($1,$2,$3,$4,$4,$5,$6) RETURNING *`,
        [rid, poi.rows[0].product_id, it.batch_code||null, qty, it.unit_cost||poi.rows[0].unit_price, it.expiration_date||null]);
      await client.query(
        `INSERT INTO stock_movements (restaurant_id, product_id, batch_id, user_id, type, quantity, reason, notes)
         VALUES ($1,$2,$3,$4,'entrada',$5,'purchase',$6)`,
        [rid, poi.rows[0].product_id, batch.rows[0].id, req.user.id, qty, `Recepción pedido #${req.params.id}`]);
      await syncStock(client, poi.rows[0].product_id);
    }
    const check = await client.query(
      'SELECT COUNT(*) FROM purchase_order_items WHERE purchase_order_id=$1 AND received_quantity < quantity', [req.params.id]);
    const done = Number(check.rows[0].count) === 0;
    await client.query('UPDATE purchase_orders SET status=$1, received_date=$2 WHERE id=$3',
      [done ? 'received' : 'sent', done ? new Date() : null, req.params.id]);
    await audit(client, rid, req.user.id, 'purchase.received', 'purchase_order', req.params.id, { done });
    await client.query('COMMIT');
    res.json({ ok: true, status: done ? 'received' : 'partial' });
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

// ---------- RECETAS ----------
app.get('/api/recipes', auth, requireSubscription, async (req, res) => {
  const rid = req.user.restaurantId;
  const recipes = await pool.query('SELECT * FROM recipes WHERE restaurant_id=$1 AND active=true ORDER BY name', [rid]);
  const out = [];
  for (const r of recipes.rows) {
    const ings = await pool.query(
      `SELECT ri.*, p.name AS product_name, p.purchase_price, p.unit AS product_unit
       FROM recipe_ingredients ri JOIN products p ON p.id=ri.product_id WHERE ri.recipe_id=$1`, [r.id]);
    const cost = ings.rows.reduce((s, i) => s + Number(i.quantity) * Number(i.purchase_price), 0);
    out.push({ ...r, ingredients: ings.rows, cost, margin: r.selling_price > 0 ? ((r.selling_price - cost) / r.selling_price * 100) : 0 });
  }
  res.json(out);
});
app.post('/api/recipes', auth, requireSubscription, requireRole('admin','manager'), async (req, res) => {
  const { name, description, selling_price, ingredients } = req.body;
  if (!name || !Array.isArray(ingredients) || ingredients.length === 0)
    return res.status(400).json({ error: 'Nombre y al menos un ingrediente son obligatorios' });
  const rid = req.user.restaurantId;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rec = await client.query(
      'INSERT INTO recipes (restaurant_id, name, description, selling_price) VALUES ($1,$2,$3,$4) RETURNING *',
      [rid, name, description, selling_price]);
    for (const ing of ingredients) {
      await client.query(
        'INSERT INTO recipe_ingredients (recipe_id, product_id, quantity, unit) VALUES ($1,$2,$3,$4)',
        [rec.rows[0].id, ing.product_id, ing.quantity, ing.unit]);
    }
    await audit(client, rid, req.user.id, 'recipe.created', 'recipe', rec.rows[0].id, { name });
    await client.query('COMMIT');
    res.status(201).json(rec.rows[0]);
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});

// ---------- VENTAS ----------
app.post('/api/sales', auth, requireSubscription, requireRole('admin','manager','kitchen'), async (req, res) => {
  const { recipe_id, quantity } = req.body;
  const qtySale = Number(quantity) || 1;
  if (!recipe_id || qtySale <= 0) return res.status(400).json({ error: 'Receta y cantidad válidas son obligatorias' });
  const rid = req.user.restaurantId;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rec = await client.query('SELECT * FROM recipes WHERE id=$1 AND restaurant_id=$2 AND active=true', [recipe_id, rid]);
    if (!rec.rows[0]) throw new Error('Receta no encontrada');
    const ings = await client.query(
      `SELECT ri.*, p.name AS product_name, p.unit AS product_unit
       FROM recipe_ingredients ri JOIN products p ON p.id=ri.product_id WHERE ri.recipe_id=$1`, [recipe_id]);
    const faltantes = [];
    for (const ing of ings.rows) {
      const need = Number(ing.quantity) * qtySale;
      const stock = await client.query(
        'SELECT COALESCE(SUM(quantity_remaining),0) AS total FROM product_batches WHERE product_id=$1 AND restaurant_id=$2',
        [ing.product_id, rid]);
      const disponible = Number(stock.rows[0].total);
      if (disponible < need) faltantes.push(`${ing.product_name}: necesita ${need} ${ing.product_unit}, hay ${disponible}`);
    }
    if (faltantes.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `No se puede registrar la venta. Falta stock:\n- ${faltantes.join('\n- ')}`, faltantes });
    }
    for (const ing of ings.rows) {
      let remaining = Number(ing.quantity) * qtySale;
      const lots = await client.query(
        `SELECT * FROM product_batches WHERE product_id=$1 AND restaurant_id=$2 AND quantity_remaining > 0
         ORDER BY expiration_date ASC NULLS LAST, received_date ASC FOR UPDATE`,
        [ing.product_id, rid]);
      for (const lot of lots.rows) {
        if (remaining <= 0) break;
        const take = Math.min(remaining, Number(lot.quantity_remaining));
        await client.query('UPDATE product_batches SET quantity_remaining = quantity_remaining - $1 WHERE id=$2', [take, lot.id]);
        await client.query(
          `INSERT INTO stock_movements (restaurant_id, product_id, batch_id, user_id, type, quantity, reason, notes)
           VALUES ($1,$2,$3,$4,'salida',$5,'kitchen_use',$6)`,
          [rid, ing.product_id, lot.id, req.user.id, -take, `Venta receta #${recipe_id}`]);
        remaining -= take;
      }
      await syncStock(client, ing.product_id);
    }
    const total = Number(rec.rows[0].selling_price) * qtySale;
    const sale = await client.query(
      'INSERT INTO sales (restaurant_id, user_id, recipe_id, quantity, unit_price, total) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [rid, req.user.id, recipe_id, qtySale, rec.rows[0].selling_price, total]);
    await audit(client, rid, req.user.id, 'sale.created', 'sale', sale.rows[0].id, { recipe_id, quantity: qtySale, total });
    await client.query('COMMIT');
    res.status(201).json(sale.rows[0]);
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});
app.get('/api/sales', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT s.*, r.name AS recipe_name FROM sales s JOIN recipes r ON r.id=s.recipe_id
     WHERE s.restaurant_id=$1 ORDER BY s.sale_date DESC LIMIT 200`, [req.user.restaurantId]);
  res.json(rows);
});

// ---------- AUDITORÍA ----------
app.get('/api/audit-logs', auth, requireSubscription, requireRole('admin','manager'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT a.*, u.full_name AS user_name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
     WHERE a.restaurant_id=$1 ORDER BY a.created_at DESC LIMIT 200`, [req.user.restaurantId]);
  res.json(rows);
});

// ---------- CADUCIDADES ----------
app.get('/api/batches/expiring', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT b.*, p.name AS product_name, p.unit FROM product_batches b JOIN products p ON p.id=b.product_id
     WHERE b.restaurant_id=$1 AND b.quantity_remaining > 0 AND b.expiration_date IS NOT NULL
       AND b.expiration_date <= CURRENT_DATE + 30 ORDER BY b.expiration_date ASC`, [req.user.restaurantId]);
  const today = new Date();
  res.json(rows.map(r => {
    const days = Math.ceil((new Date(r.expiration_date) - today) / 86400000);
    const level = days < 0 ? 'expired' : days <= 3 ? 'danger' : days <= 7 ? 'warn' : 'ok';
    return { ...r, days_left: days, level };
  }));
});

// ---------- INFORMES ----------
app.get('/api/reports/top-consumed', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT p.name, SUM(ABS(m.quantity)) AS total FROM stock_movements m JOIN products p ON p.id=m.product_id
     WHERE m.restaurant_id=$1 AND m.type='salida' AND m.reason='kitchen_use'
     GROUP BY p.name ORDER BY total DESC LIMIT 10`, [req.user.restaurantId]);
  res.json(rows);
});
app.get('/api/reports/waste', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT p.name, m.reason, SUM(ABS(m.quantity)) AS total, SUM(ABS(m.quantity)*p.purchase_price) AS value
     FROM stock_movements m JOIN products p ON p.id=m.product_id
     WHERE m.restaurant_id=$1 AND m.type='salida' AND m.reason IN ('waste','expired','breakage')
     GROUP BY p.name, m.reason ORDER BY value DESC`, [req.user.restaurantId]);
  res.json(rows);
});
app.get('/api/reports/sales-summary', auth, requireSubscription, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT date_trunc('day', sale_date) AS day, COUNT(*) AS count, SUM(total) AS total
     FROM sales WHERE restaurant_id=$1 AND sale_date >= CURRENT_DATE - 30 GROUP BY day ORDER BY day`, [req.user.restaurantId]);
  res.json(rows);
});

// ---------- HEALTH ----------
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', ts: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ status: 'error', error: e.message });
  }
});

// ---------- SEED ----------
async function ensureAdmin() {
  const admin = await pool.query("SELECT id FROM users WHERE email='admin@demo.com'");
  if (admin.rows.length === 0) {
    const hash = await bcrypt.hash('Admin12345', 10);
    await pool.query(
      'INSERT INTO users (restaurant_id, email, password_hash, full_name, role, last_login_at) VALUES (1,$1,$2,$3,$4,NOW())',
      ['admin@demo.com', hash, 'Admin Demo', 'admin']);
    log('info', 'admin creado', { email: 'admin@demo.com' });
  } else {
    log('info', 'admin ya existe', { id: admin.rows[0].id });
  }
  const sup = await pool.query("SELECT id FROM users WHERE email='super@demo.com'");
  if (sup.rows.length === 0) {
    const hash = await bcrypt.hash('Super12345', 10);
    await pool.query(
      'INSERT INTO users (restaurant_id, email, password_hash, full_name, role, last_login_at) VALUES (NULL,$1,$2,$3,$4,NOW())',
      ['super@demo.com', hash, 'Super Admin', 'superadmin']);
    log('info', 'superadmin creado', { email: 'super@demo.com' });
  }
}

// ---------- MANEJO DE ERRORES ----------
app.use((err, req, res, next) => {
  log('error', 'no controlado', { error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Error interno del servidor' });
});

// ---------- ARRANQUE ----------
const PORT = process.env.PORT || 3000;

async function start() {
  try {
    log('info', 'Probando conexión a PostgreSQL...', {
      host: process.env.PGHOST,
      port: process.env.PGPORT,
      user: process.env.PGUSER,
      database: process.env.PGDATABASE,
    });
    await pool.query('SELECT 1');
    log('info', 'PostgreSQL conectado');
    await ensureAdmin();
    app.listen(PORT, '0.0.0.0', () => log('info', `API en http://localhost:${PORT}`));
  } catch (err) {
    log('error', 'Error PostgreSQL', {
      message: err.message,
      code: err.code,
      host: process.env.PGHOST,
      port: process.env.PGPORT,
      user: process.env.PGUSER,
      database: process.env.PGDATABASE,
    });
    process.exit(1);
  }
}
start();