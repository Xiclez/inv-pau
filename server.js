const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3010;

// Detras de un reverse proxy (Nginx / Traefik / Cloudflare) necesitamos confiar
// en X-Forwarded-Proto y X-Forwarded-Host para construir URLs absolutas correctas.
app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '7d' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});

// --- CONFIGURACION ---

const SESSION_TTL_SECONDS = 10 * 60; // 10 minutos de inactividad
const COOKIE_NAME = 'pau_admin';

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'itwasneveraphase';
const USING_DEFAULT_CREDENTIALS = !process.env.ADMIN_USER || !process.env.ADMIN_PASSWORD;

// El secreto se persiste en disco para que los reinicios del contenedor no
// invaliden todas las sesiones y para no depender de una variable de entorno.
const SECRET_FILE = path.join(__dirname, 'data', '.jwt-secret');
const JWT_SECRET = resolveSecret();

function resolveSecret() {
    if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
    try {
        if (fs.existsSync(SECRET_FILE)) return fs.readFileSync(SECRET_FILE, 'utf8').trim();
        const generated = crypto.randomBytes(48).toString('hex');
        fs.mkdirSync(path.dirname(SECRET_FILE), { recursive: true });
        fs.writeFileSync(SECRET_FILE, generated, { mode: 0o600 });
        return generated;
    } catch (err) {
        console.warn('No se pudo persistir JWT_SECRET, usando secreto efimero:', err.message);
        return crypto.randomBytes(48).toString('hex');
    }
}

// --- BASE DE DATOS ---

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'invitados.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error('Error conectando a la base de datos:', err);
    else console.log('Conectado a SQLite DB - listo para el mosh pit!');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS guests (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        rsvp_status TEXT NOT NULL DEFAULT 'pending'
    )`);
    // Columnas agregadas despues de la version inicial: ignoramos el error de
    // "duplicate column" para que la migracion sea idempotente.
    const addColumn = (sql) => db.run(sql, (err) => {
        if (err && !/duplicate column/i.test(err.message)) console.error(err.message);
    });
    addColumn("ALTER TABLE guests ADD COLUMN created_at TEXT");
    addColumn("ALTER TABLE guests ADD COLUMN opened_at TEXT");
    addColumn("ALTER TABLE guests ADD COLUMN responded_at TEXT");
});

// --- JWT (HS256 implementado con crypto, sin dependencias extra) ---

const b64url = (input) => Buffer.from(input).toString('base64url');

function signToken(payload, ttlSeconds) {
    const issuedAt = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const body = b64url(JSON.stringify({ ...payload, iat: issuedAt, exp: issuedAt + ttlSeconds }));
    const data = `${header}.${body}`;
    const signature = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
    return `${data}.${signature}`;
}

function verifyToken(token) {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const data = `${parts[0]}.${parts[1]}`;
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
    const given = Buffer.from(parts[2]);
    const mine = Buffer.from(expected);
    if (given.length !== mine.length || !crypto.timingSafeEqual(given, mine)) return null;

    try {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        if (typeof payload.exp !== 'number' || payload.exp <= Math.floor(Date.now() / 1000)) return null;
        return payload;
    } catch {
        return null;
    }
}

function parseCookies(req) {
    const header = req.headers.cookie;
    if (!header) return {};
    return header.split(';').reduce((acc, pair) => {
        const index = pair.indexOf('=');
        if (index < 0) return acc;
        acc[pair.slice(0, index).trim()] = decodeURIComponent(pair.slice(index + 1).trim());
        return acc;
    }, {});
}

function issueSession(req, res, username) {
    const token = signToken({ sub: username }, SESSION_TTL_SECONDS);
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        sameSite: 'lax',
        secure: req.secure,
        maxAge: SESSION_TTL_SECONDS * 1000,
        path: '/'
    });
}

// Cada request autenticado renueva el token: la expiracion es por inactividad.
function makeAuth(onFailure) {
    return function (req, res, next) {
        const payload = verifyToken(parseCookies(req)[COOKIE_NAME]);
        if (!payload) {
            res.clearCookie(COOKIE_NAME, { path: '/' });
            return onFailure(req, res);
        }
        req.admin = payload.sub;
        issueSession(req, res, payload.sub);
        next();
    };
}

const requireAuth = makeAuth((req, res) =>
    res.redirect('/admin/login?next=' + encodeURIComponent(req.originalUrl)));

// El heartbeat nunca redirige: fetch() seguiria el 302 hasta el login y
// devolveria 200, haciendo creer al cliente que la sesion sigue viva.
const requireAuthJson = makeAuth((req, res) =>
    res.status(401).json({ error: 'unauthorized' }));

// --- CREDENCIALES ---

const PASSWORD_SALT = crypto.createHash('sha256').update(ADMIN_USER).digest();
const PASSWORD_HASH = crypto.scryptSync(ADMIN_PASSWORD, PASSWORD_SALT, 64);

function checkCredentials(username, password) {
    const userOk = safeEqual(String(username || ''), ADMIN_USER);
    const candidate = crypto.scryptSync(String(password || ''), PASSWORD_SALT, 64);
    const passOk = crypto.timingSafeEqual(candidate, PASSWORD_HASH);
    return userOk && passOk;
}

function safeEqual(a, b) {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

// Rate limit simple en memoria para frenar fuerza bruta contra el login.
const loginAttempts = new Map();
const MAX_ATTEMPTS = 8;
const LOCKOUT_MS = 10 * 60 * 1000;

function loginThrottle(req, res, next) {
    const key = req.ip;
    const record = loginAttempts.get(key);
    if (record && record.count >= MAX_ATTEMPTS && Date.now() < record.until) {
        const minutes = Math.ceil((record.until - Date.now()) / 60000);
        return res.status(429).render('login', {
            error: `Demasiados intentos. Espera ${minutes} min.`,
            next: ''
        });
    }
    next();
}

function registerFailedLogin(ip) {
    const record = loginAttempts.get(ip) || { count: 0, until: 0 };
    record.count += 1;
    record.until = Date.now() + LOCKOUT_MS;
    loginAttempts.set(ip, record);
}

// --- UTILIDADES ---

function baseUrl(req) {
    // BASE_URL permite fijar el dominio publico cuando el proxy no reenvia Host.
    if (process.env.BASE_URL) return process.env.BASE_URL.replace(/\/+$/, '');
    return `${req.protocol}://${req.get('host')}`;
}

const nowIso = () => new Date().toISOString();

// --- RUTAS DE ADMIN ---

app.get('/admin/login', (req, res) => {
    if (verifyToken(parseCookies(req)[COOKIE_NAME])) return res.redirect('/admin');
    res.render('login', { error: null, next: req.query.next || '' });
});

app.post('/admin/login', loginThrottle, (req, res) => {
    const { username, password } = req.body;
    if (!checkCredentials(username, password)) {
        registerFailedLogin(req.ip);
        return res.status(401).render('login', {
            error: 'Usuario o contraseña incorrectos.',
            next: req.body.next || ''
        });
    }
    loginAttempts.delete(req.ip);
    issueSession(req, res, ADMIN_USER);
    const target = typeof req.body.next === 'string' && req.body.next.startsWith('/admin') ? req.body.next : '/admin';
    res.redirect(target);
});

app.post('/admin/logout', (req, res) => {
    res.clearCookie(COOKIE_NAME, { path: '/' });
    res.redirect('/admin/login');
});

app.get('/admin', requireAuth, (req, res) => {
    db.all('SELECT * FROM guests ORDER BY datetime(created_at) DESC, name ASC', [], (err, rows) => {
        if (err) return res.status(500).send('Error en la DB');
        res.render('admin', {
            guests: rows,
            hostUrl: baseUrl(req),
            sessionMinutes: SESSION_TTL_SECONDS / 60,
            insecureDefaults: USING_DEFAULT_CREDENTIALS
        });
    });
});

// Heartbeat: renueva la cookie mientras el admin siga interactuando con la pagina.
app.get('/admin/ping', requireAuthJson, (req, res) => res.json({ ok: true }));

app.post('/admin/invite', requireAuth, (req, res) => {
    const name = String(req.body.name || '').trim().slice(0, 60);
    if (!name) return res.redirect('/admin');
    const id = crypto.randomBytes(8).toString('hex');
    db.run('INSERT INTO guests (id, name, created_at) VALUES (?, ?, ?)', [id, name, nowIso()], (err) => {
        if (err) return res.status(500).send('Error al guardar en DB');
        res.redirect('/admin');
    });
});

app.post('/admin/guest/:id/status', requireAuth, (req, res) => {
    const status = ['pending', 'confirmed', 'declined'].includes(req.body.status) ? req.body.status : 'pending';
    const responded = status === 'pending' ? null : nowIso();
    db.run('UPDATE guests SET rsvp_status = ?, responded_at = ? WHERE id = ?', [status, responded, req.params.id], (err) => {
        if (err) return res.status(500).send('Error al actualizar');
        res.redirect('/admin');
    });
});

app.post('/admin/guest/:id/delete', requireAuth, (req, res) => {
    db.run('DELETE FROM guests WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).send('Error al borrar');
        res.redirect('/admin');
    });
});

app.get('/admin/export.csv', requireAuth, (req, res) => {
    db.all('SELECT name, rsvp_status, created_at, opened_at, responded_at, id FROM guests ORDER BY name', [], (err, rows) => {
        if (err) return res.status(500).send('Error en la DB');
        const escape = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
        const lines = [['nombre', 'estado', 'creado', 'abierto', 'respondido', 'link'].join(',')];
        for (const row of rows) {
            lines.push([
                row.name, row.rsvp_status, row.created_at, row.opened_at, row.responded_at,
                `${baseUrl(req)}/invite/${row.id}`
            ].map(escape).join(','));
        }
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="invitados.csv"');
        res.send('﻿' + lines.join('\n'));
    });
});

// --- RUTAS PUBLICAS (INVITADOS) ---

app.get('/invite/:id', (req, res) => {
    db.get('SELECT * FROM guests WHERE id = ?', [req.params.id], (err, row) => {
        if (err || !row) return res.status(404).send('Invitación no encontrada (it was just a phase).');
        res.render('invite', {
            guestName: row.name,
            guestId: row.id,
            rsvpStatus: row.rsvp_status,
            hostUrl: baseUrl(req),
            mapsUrl: process.env.MAPS_URL || 'https://maps.app.goo.gl/cAFySZyVNRTjwFV19'
        });
    });
});

// Marca la primera apertura del sobre (metrica para el dashboard).
app.post('/api/open/:id', (req, res) => {
    db.run('UPDATE guests SET opened_at = COALESCE(opened_at, ?) WHERE id = ?', [nowIso(), req.params.id], (err) => {
        res.json({ success: !err });
    });
});

app.post('/api/rsvp/:id', (req, res) => {
    const status = req.body && req.body.status === 'declined' ? 'declined' : 'confirmed';
    db.run(
        'UPDATE guests SET rsvp_status = ?, responded_at = ? WHERE id = ?',
        [status, nowIso(), req.params.id],
        function (err) {
            if (err) return res.status(500).json({ success: false });
            if (this.changes === 0) return res.status(404).json({ success: false });
            res.json({ success: true, status });
        }
    );
});

app.get('/', (req, res) => res.redirect('/admin'));

app.listen(PORT, () => {
    console.log(`Servidor de invitaciones corriendo en el puerto ${PORT}`);
    if (USING_DEFAULT_CREDENTIALS) {
        console.warn(`AVISO: usando credenciales por defecto (${ADMIN_USER}). Define ADMIN_USER y ADMIN_PASSWORD.`);
    }
});
