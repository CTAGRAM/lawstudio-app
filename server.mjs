import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import path from 'path';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.join(__dirname, 'dist');
app.use(express.json());
app.use(cookieParser());

const EMAIL = process.env.LOGIN_EMAIL || '';
const PASS = process.env.LOGIN_PASSWORD || '';
const SECRET = process.env.AUTH_SECRET || 'change-me';
const token = () => crypto.createHmac('sha256', SECRET).update(EMAIL).digest('hex');
const authed = (req) => req.cookies && req.cookies.ls_auth === token();

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (email === EMAIL && password === PASS) {
    res.cookie('ls_auth', token(), { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 30 * 864e5 });
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: 'Wrong email or password' });
});
app.post('/api/logout', (_req, res) => { res.clearCookie('ls_auth'); res.json({ ok: true }); });

// static assets (js/css/img) are fine to serve; the app itself is gated at the HTML level
app.use('/assets', express.static(path.join(DIST, 'assets')));
app.get(['/favicon.png', '/favicon.svg', '/icons.svg', '/logo-64.png', '/logo-192.png', '/logo-512.png'],
  (req, res) => res.sendFile(path.join(DIST, req.path)));

app.get('*', (req, res) => {
  if (!authed(req)) return res.sendFile(path.join(__dirname, 'login.html'));
  res.sendFile(path.join(DIST, 'index.html'));
});
app.listen(process.env.PORT || 8000, () => console.log('lawstudio on', process.env.PORT || 8000));
