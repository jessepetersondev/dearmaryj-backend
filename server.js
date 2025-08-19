import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import dotenv from 'dotenv';
import pkg from 'pg';
const { Pool } = pkg;
import bodyParser from 'body-parser';

dotenv.config();

const {
  PORT = 8080,
  STRIPE_SECRET_KEY,
  STRIPE_PAYMENT_LINK_URL,
  STRIPE_PRICE_ID,
  STRIPE_WEBHOOK_SECRET, // optional but recommended
  JWT_SECRET,
  COOKIE_NAME = 'dmj_auth',
  COOKIE_DOMAIN,
  COOKIE_SECURE = 'true',
  APP_DOMAIN_ORIGIN,
  DATABASE_URL // optional but recommended for restore
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

// --- Optional: DB for cross-device lifetime restore ---
let pool = null;
(async () => {
  if (DATABASE_URL) {
    pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dmj_entitlements (
        customer_id TEXT PRIMARY KEY,
        email TEXT,
        price_id TEXT,
        latest_session_id TEXT UNIQUE,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS dmj_entitlements_email_idx ON dmj_entitlements ((lower(email)));
    `);
  }
})().catch(e => console.error('DB init error', e));

// --- Helpers ---
function uaHash(ua) {
  return crypto.createHash('sha256').update(String(ua || '')).digest('hex');
}

function signAuthCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1095d' }); // ~3 years
  const cookieOpts = {
    httpOnly: true,
    secure: COOKIE_SECURE === 'true',
    sameSite: 'lax',
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 365 * 3 // 3 years
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

// --- Rate limit for sensitive endpoints ---
const validateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Routes ---
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Redirect to Stripe Payment Link (no secrets on client)
app.get('/api/pay', (req, res) => {
  res.redirect(302, STRIPE_PAYMENT_LINK_URL);
});

// Client checks if already unlocked (cookie)
app.get('/api/auth/status', (req, res) => {
  res.json({ unlocked: verifyAuth(req) });
});

// Validate Stripe Checkout session on return from success
app.post('/api/validate-session', validateLimiter, async (req, res) => {
  try {
    const { session_id } = req.body || {};
    if (!session_id) return res.status(400).json({ error: 'Missing session_id' });

    // Verify with Stripe
    const session = await stripe.checkout.sessions.retrieve(session_id, { expand: ['line_items.data.price'] });
    if (!session || session.mode !== 'payment') return res.status(400).json({ error: 'Invalid session' });

    const paid = (session.payment_status === 'paid') || (session.status === 'complete');
    if (!paid) return res.status(402).json({ error: 'Payment not completed' });

    // Ensure expected price was purchased
    const items = session.line_items?.data || [];
    const hasExpectedPrice = items.some(i => i.price?.id === STRIPE_PRICE_ID);
    if (!hasExpectedPrice) return res.status(400).json({ error: 'Unexpected price' });

    // Persist entitlement (optional but recommended)
    const email = session.customer_details?.email || null;
    const customerId = session.customer || null;

    if (pool && (email || customerId)) {
      try {
        await pool.query(`
          INSERT INTO dmj_entitlements (customer_id, email, price_id, latest_session_id, active)
          VALUES ($1,$2,$3,$4,TRUE)
          ON CONFLICT (customer_id) DO UPDATE SET
            email=EXCLUDED.email,
            price_id=EXCLUDED.price_id,
            latest_session_id=EXCLUDED.latest_session_id,
            active=TRUE,
            updated_at=now();
        `, [customerId || `guest:${email || 'unknown'}`, email, STRIPE_PRICE_ID, session.id]);
      } catch (dbErr) {
        console.error('DB upsert error', dbErr);
      }
    }

    // Issue long-lived HttpOnly cookie (lightly bound to UA)
    const uah = uaHash(req.headers['user-agent']);
    signAuthCookie(res, { sub: `checkout:${session.id}`, scope: 'unlocked', uah });

    res.json({ unlocked: true });
  } catch (err) {
    console.error('validate-session error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Restore across devices by email (requires DATABASE_URL + webhook/validate-session persistence)
app.post('/api/restore', async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ error: 'Restore requires DATABASE_URL configured.' });
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email required' });

    const r = await pool.query(`SELECT customer_id FROM dmj_entitlements WHERE lower(email)=$1 AND active=TRUE LIMIT 1`, [email]);
    if (!r.rows.length) return res.status(404).json({ error: 'No active purchase found for that email.' });

    const uah = uaHash(req.headers['user-agent']);
    signAuthCookie(res, { sub: `restore:${r.rows[0].customer_id}`, scope: 'unlocked', uah });
    res.json({ unlocked: true });
  } catch (e) {
    console.error('restore error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Stripe webhook to persist entitlements robustly (checkout.session.completed)
app.post('/webhooks/stripe', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) return res.status(400).send('Webhook not configured');
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      if (session.payment_status !== 'paid') return res.json({ received: true });

      const full = await stripe.checkout.sessions.retrieve(session.id, { expand: ['line_items.data.price'] });
      const items = full.line_items?.data || [];
      const hasExpectedPrice = items.some(i => i.price?.id === STRIPE_PRICE_ID);
      if (!hasExpectedPrice) return res.json({ received: true });

      if (pool) {
        const email = full.customer_details?.email || null;
        const customerId = full.customer || null;
        await pool.query(`
          INSERT INTO dmj_entitlements (customer_id, email, price_id, latest_session_id, active)
          VALUES ($1,$2,$3,$4,TRUE)
          ON CONFLICT (customer_id) DO UPDATE SET
            email=EXCLUDED.email,
            price_id=EXCLUDED.price_id,
            latest_session_id=EXCLUDED.latest_session_id,
            active=TRUE,
            updated_at=now();
        `, [customerId || `guest:${email || 'unknown'}`, email, STRIPE_PRICE_ID, full.id]);
      }
    }
    res.json({ received: true });
  } catch (e) {
    console.error('Webhook handler error', e);
    res.status(500).send('Webhook handler error');
  }
});

// Optional logout helper
app.post('/api/logout', (req, res) => { clearAuthCookie(res); res.json({ ok: true }); });

app.listen(PORT, () => console.log(`DMJ backend running on :${PORT}`));
