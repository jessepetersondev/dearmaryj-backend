import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const {
  PORT = 8080,
  NODE_ENV = 'development',
  STRIPE_SECRET_KEY,
  STRIPE_PAYMENT_LINK_URL,
  STRIPE_PRICE_ID,
  JWT_SECRET,
  COOKIE_NAME = 'dmj_auth',
  COOKIE_DOMAIN,
  COOKIE_SECURE = 'true',
  APP_DOMAIN_ORIGIN,
} = process.env;

if (!STRIPE_SECRET_KEY || !STRIPE_PAYMENT_LINK_URL || !STRIPE_PRICE_ID || !JWT_SECRET || !APP_DOMAIN_ORIGIN) {
  console.error('Missing required env vars. Please set STRIPE_SECRET_KEY, STRIPE_PAYMENT_LINK_URL, STRIPE_PRICE_ID, JWT_SECRET, APP_DOMAIN_ORIGIN');
  process.exit(1);
}

const app = express();
app.use(cors({ origin: APP_DOMAIN_ORIGIN, credentials: true }));
app.use(express.json());
app.use(cookieParser());
const stripe = new Stripe(STRIPE_SECRET_KEY);

function uaHash(ua) {
  return crypto.createHash('sha256').update(String(ua || '')).digest('hex');
}

function signAuthCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '730d' });
  const cookieOpts = {
    httpOnly: true,
    secure: COOKIE_SECURE === 'true',
    sameSite: 'lax',
    path: '/',
  };
  if (COOKIE_DOMAIN) cookieOpts.domain = COOKIE_DOMAIN;
  res.cookie(COOKIE_NAME, token, cookieOpts);
}

function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

function verifyAuth(req) {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return false;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const expected = uaHash(req.headers['user-agent']);
    if (decoded.uah !== expected) return false;
    if (decoded.scope !== 'unlocked') return false;
    return true;
  } catch (e) {
    return false;
  }
}

const validateLimiter = rateLimit({ windowMs: 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false });

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/pay', (req, res) => res.redirect(302, STRIPE_PAYMENT_LINK_URL));
app.get('/api/auth/status', (req, res) => res.json({ unlocked: verifyAuth(req) }));

app.post('/api/validate-session', validateLimiter, async (req, res) => {
  try {
    const { session_id } = req.body || {};
    if (!session_id) return res.status(400).json({ error: 'Missing session_id' });

    const session = await stripe.checkout.sessions.retrieve(session_id, { expand: ['line_items.data.price'] });
    if (!session || session.mode !== 'payment') return res.status(400).json({ error: 'Invalid session' });

    const paid = (session.payment_status === 'paid') || (session.status === 'complete');
    if (!paid) return res.status(402).json({ error: 'Payment not completed' });

    const items = session.line_items?.data || [];
    const hasExpectedPrice = items.some(i => i.price?.id === STRIPE_PRICE_ID);
    if (!hasExpectedPrice) return res.status(400).json({ error: 'Unexpected price' });

    const uah = uaHash(req.headers['user-agent']);
    signAuthCookie(res, { sub: `checkout:${session.id}`, scope: 'unlocked', uah });

    res.json({ unlocked: true });
  } catch (err) {
    console.error('validate-session error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => { clearAuthCookie(res); res.json({ ok: true }); });

app.listen(PORT, () => console.log(`DMJ backend running on :${PORT}`));
