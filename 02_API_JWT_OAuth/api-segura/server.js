'use strict';
/**
 * Actividad 4 – API simulada "ClinicApp" con controles de seguridad
 *  - OAuth 2.0 (grant client_credentials)  -> POST /oauth/token
 *  - Autenticación de usuario con JWT        -> POST /auth/login
 *  - Autorización por scopes (mínimo privilegio)
 *  - Validación estricta de entradas (lista blanca) contra inyección
 *  - Rate limiting: 100 solicitudes/minuto en /api, 10/minuto en endpoints de token
 *
 * Uso:  npm install && npm start   (http://localhost:3000)
 * Variables opcionales: PORT, JWT_SECRET, CLIENT_SECRET, USER_PASSWORD
 */
const express = require('express');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { rateLimit } = require('express-rate-limit');

const PORT = process.env.PORT || 3000;
// Secreto de 256 bits; si no se define, se genera uno aleatorio en cada arranque.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ISSUER = 'clinicapp-auth';
const AUDIENCE = 'clinicapp-api';
const TOKEN_TTL = 15 * 60; // 15 minutos

// Cliente OAuth registrado (laboratorio). En producción: secretos con hash en un almacén seguro.
const OAUTH_CLIENTS = {
  'postman-lab': {
    secret: process.env.CLIENT_SECRET || 'lab-secret-cambiar',
    scopes: ['citas:read', 'citas:write'],
  },
};
// Usuario de laboratorio: solo lectura (mínimo privilegio).
const USERS = {
  recepcion: { password: process.env.USER_PASSWORD || 'Recepcion#2026', scopes: ['citas:read'] },
};

// Datos simulados. Con una BD real se usaría una consulta parametrizada, p. ej.:
//   db.prepare('SELECT id, fecha, motivo FROM citas WHERE paciente = ?').all(paciente)
const citas = [
  { id: 1, paciente: 101, fecha: '2026-11-12', motivo: 'Consulta general' },
  { id: 2, paciente: 101, fecha: '2026-11-20', motivo: 'Resultados de laboratorio' },
  { id: 3, paciente: 102, fecha: '2026-11-13', motivo: 'Vacunación' },
];
let siguienteId = 4;

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ---------- Rate limiting ----------
const respuesta429 = (detalle) => (req, res, next, options) =>
  res.status(options.statusCode).json({ error: 'too_many_requests', detalle });

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7', // cabeceras RateLimit y RateLimit-Policy
  legacyHeaders: false,
  handler: respuesta429('Límite de 100 solicitudes por minuto excedido'),
});
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10, // freno a fuerza bruta de credenciales
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: respuesta429('Demasiados intentos de autenticación'),
});

// ---------- Utilidades ----------
function igualSeguro(a, b) {
  const ba = Buffer.from(String(a ?? ''));
  const bb = Buffer.from(String(b ?? ''));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function emitirToken(sub, scopes, tipo) {
  return jwt.sign({ scope: scopes.join(' '), tipo }, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: TOKEN_TTL,
    issuer: ISSUER,
    audience: AUDIENCE,
    subject: sub,
    jwtid: crypto.randomUUID(),
  });
}

function responderToken(res, sub, scopes, tipo) {
  res.set('Cache-Control', 'no-store');
  res.json({
    access_token: emitirToken(sub, scopes, tipo),
    token_type: 'Bearer',
    expires_in: TOKEN_TTL,
    scope: scopes.join(' '),
  });
}

// ---------- Endpoints de autenticación ----------
// OAuth 2.0 Client Credentials (RFC 6749 §4.4)
app.post('/oauth/token', authLimiter, (req, res) => {
  const { grant_type, client_id, client_secret, scope } = req.body || {};
  if (grant_type !== 'client_credentials') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  if (typeof client_id !== 'string' || !Object.hasOwn(OAUTH_CLIENTS, client_id)
      || !igualSeguro(client_secret, OAUTH_CLIENTS[client_id].secret)) {
    return res.status(401).json({ error: 'invalid_client' });
  }
  const permitidos = OAUTH_CLIENTS[client_id].scopes;
  const pedidos = typeof scope === 'string' && scope.trim() ? scope.trim().split(/\s+/) : permitidos;
  if (!pedidos.every((s) => permitidos.includes(s))) {
    return res.status(400).json({ error: 'invalid_scope' });
  }
  return responderToken(res, client_id, pedidos, 'client');
});

// Login de usuario -> JWT
app.post('/auth/login', authLimiter, (req, res) => {
  const { usuario, password } = req.body || {};
  const ok = typeof usuario === 'string' && Object.hasOwn(USERS, usuario)
    && igualSeguro(password, USERS[usuario].password);
  if (!ok) return res.status(401).json({ error: 'credenciales_invalidas' }); // mensaje genérico
  return responderToken(res, usuario, USERS[usuario].scopes, 'usuario');
});

// ---------- Middleware de autorización ----------
function autenticar(req, res, next) {
  const [tipo, token] = (req.get('authorization') || '').split(' ');
  if (tipo !== 'Bearer' || !token) {
    return res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'token_requerido' });
  }
  try {
    // Lista blanca de algoritmos: rechaza "none" y cualquier otro algoritmo.
    req.auth = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], issuer: ISSUER, audience: AUDIENCE });
    return next();
  } catch {
    return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'token_invalido' });
  }
}

const requiereScope = (scope) => (req, res, next) =>
  String(req.auth.scope || '').split(' ').includes(scope)
    ? next()
    : res.status(403).json({ error: 'insufficient_scope', requerido: scope });

// ---------- Validación de entradas (lista blanca) ----------
const RE_ID = /^[1-9]\d{0,5}$/; // entero positivo de hasta 6 dígitos
const RE_TEXTO = /^[\p{L}\p{N} .,()-]{3,100}$/u; // letras, números y puntuación básica

function fechaValida(v) {
  return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v)
    && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString().slice(0, 10) === v;
}

function validarConsulta(req, res, next) {
  const claves = Object.keys(req.query);
  if (claves.length !== 1 || claves[0] !== 'paciente') {
    return res.status(400).json({ error: 'parametros_no_permitidos', permitidos: ['paciente'] });
  }
  const { paciente } = req.query;
  if (typeof paciente !== 'string' || !RE_ID.test(paciente)) {
    return res.status(400).json({ error: 'paciente_invalido', formato: 'entero positivo de hasta 6 dígitos' });
  }
  req.valido = { paciente: Number(paciente) };
  return next();
}

function validarNuevaCita(req, res, next) {
  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'cuerpo_invalido' });
  }
  const permitidas = ['paciente', 'fecha', 'motivo'];
  const extras = Object.keys(body).filter((k) => !permitidas.includes(k));
  if (extras.length) return res.status(400).json({ error: 'campos_no_permitidos', campos: extras });

  const errores = [];
  if (!Number.isInteger(body.paciente) || !RE_ID.test(String(body.paciente))) errores.push('paciente');
  if (!fechaValida(body.fecha)) errores.push('fecha');
  if (typeof body.motivo !== 'string' || !RE_TEXTO.test(body.motivo)) errores.push('motivo');
  if (errores.length) return res.status(400).json({ error: 'validacion', campos: errores });

  req.valido = { paciente: body.paciente, fecha: body.fecha, motivo: body.motivo };
  return next();
}

// ---------- API protegida ----------
app.use('/api', apiLimiter, autenticar);

app.get('/api/citas', requiereScope('citas:read'), validarConsulta, (req, res) => {
  res.json(citas.filter((c) => c.paciente === req.valido.paciente));
});

app.post('/api/citas', requiereScope('citas:write'), validarNuevaCita, (req, res) => {
  const cita = { id: siguienteId++, ...req.valido };
  citas.push(cita);
  res.status(201).json(cita);
});

// ---------- Errores sin filtrar detalles internos ----------
app.use((req, res) => res.status(404).json({ error: 'no_encontrado' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'json_invalido' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'cuerpo_demasiado_grande' });
  console.error(err);
  return res.status(500).json({ error: 'error_interno' });
});

app.listen(PORT, () => console.log(`API de laboratorio en http://localhost:${PORT}`));
