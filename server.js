import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import dotenv from 'dotenv';
import pkg from 'pg';
const { Pool } = pkg;
import bodyParser from 'body-parser';
import axios from 'axios';

dotenv.config();

const {
  PORT = 8080,
  BTCPAY_SERVER_URL, // e.g., https://your-btcpay-server.com
  BTCPAY_STORE_ID,
  BTCPAY_API_KEY,
  BTCPAY_WEBHOOK_SECRET, // optional but highly recommended
  BTCPAY_PAYMENT_AMOUNT, // amount in base currency (e.g., USD)
  BTCPAY_CURRENCY = 'USD', // currency code
  JWT_SECRET,
  COOKIE_NAME = 'dmj_auth',
  COOKIE_DOMAIN,
  COOKIE_SECURE = 'true',
  APP_DOMAIN_ORIGIN,
  DATABASE_URL // optional but recommended for restore
} = process.env;

if (!BTCPAY_SERVER_URL || !BTCPAY_STORE_ID || !BTCPAY_API_KEY || !BTCPAY_PAYMENT_AMOUNT || !JWT_SECRET || !APP_DOMAIN_ORIGIN) {
  console.error('Missing required env vars. Please set BTCPAY_SERVER_URL, BTCPAY_STORE_ID, BTCPAY_API_KEY, BTCPAY_PAYMENT_AMOUNT, JWT_SECRET, APP_DOMAIN_ORIGIN');
  process.exit(1);
}

console.log('=== Environment Configuration ===');
console.log('BTCPAY_SERVER_URL:', BTCPAY_SERVER_URL);
console.log('BTCPAY_STORE_ID:', BTCPAY_STORE_ID);
console.log('BTCPAY_API_KEY:', BTCPAY_API_KEY?.substring(0, 20) + '...');
console.log('BTCPAY_PAYMENT_AMOUNT:', BTCPAY_PAYMENT_AMOUNT);
console.log('BTCPAY_CURRENCY:', BTCPAY_CURRENCY);
console.log('=================================');

const app = express();

// Flexible origin list: comma-separated APP_DOMAIN_ORIGIN supported
const allowedOrigins = String(APP_DOMAIN_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: true,
}));

app.use(cookieParser());
app.set('trust proxy', 1);

// --- BTCPay Server API Helper Functions ---
const btcpayApi = {
  /**
   * Create an invoice on BTCPay Server
   * @param {Object} params - Invoice parameters
   * @returns {Promise<Object>} Invoice object
   */
  async createInvoice(params) {
    const url = `${BTCPAY_SERVER_URL}/api/v1/stores/${BTCPAY_STORE_ID}/invoices`;
    
    console.log('=== BTCPay Create Invoice Request ===');
    console.log('URL:', url);
    console.log('Store ID:', BTCPAY_STORE_ID);
    console.log('API Key (first 20 chars):', BTCPAY_API_KEY?.substring(0, 20) + '...');
    console.log('Request params:', JSON.stringify(params, null, 2));
    
    try {
      const response = await axios.post(url, params, {
        headers: {
          'Authorization': `token ${BTCPAY_API_KEY}`,
          'Content-Type': 'application/json',
        },
        timeout: 180000, // 180 seconds (3 minutes)
      });

      console.log('✅ Invoice created successfully:', response.data.id);
      return response.data;
    } catch (error) {
      console.error('❌ BTCPay API Error:', {
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
        message: error.message
      });
      if (error.response) {
        throw new Error(`BTCPay API Error: ${error.response.status} ${JSON.stringify(error.response.data)}`);
      }
      throw error;
    }
  },

  /**
   * Get invoice details from BTCPay Server
   * @param {string} invoiceId - Invoice ID
   * @returns {Promise<Object>} Invoice object
   */
  async getInvoice(invoiceId) {
    const url = `${BTCPAY_SERVER_URL}/api/v1/stores/${BTCPAY_STORE_ID}/invoices/${invoiceId}`;
    
    try {
      const response = await axios.get(url, {
        headers: {
          'Authorization': `token ${BTCPAY_API_KEY}`,
          'Content-Type': 'application/json',
        },
        timeout: 180000, // 180 seconds (3 minutes)
      });

      return response.data;
    } catch (error) {
      if (error.response) {
        throw new Error(`BTCPay API Error: ${error.response.status} ${error.response.data}`);
      }
      throw error;
    }
  },

  /**
   * Verify webhook signature
   * @param {string} payload - Raw request body
   * @param {string} signature - Signature from request header
   * @returns {boolean} True if signature is valid
   */
  verifyWebhookSignature(payload, signature) {
    if (!BTCPAY_WEBHOOK_SECRET) return true; // Skip verification if no secret is set
    
    const expectedSignature = crypto
      .createHmac('sha256', BTCPAY_WEBHOOK_SECRET)
      .update(payload)
      .digest('hex');
    
    // BTCPay sends signature as "sha256=<signature>"
    const providedSignature = signature.startsWith('sha256=') 
      ? signature.slice(7) 
      : signature;
    
    return crypto.timingSafeEqual(
      Buffer.from(expectedSignature),
      Buffer.from(providedSignature)
    );
  },
};

// --- Optional: DB for cross-device lifetime restore ---
let pool = null;
(async () => {
  if (DATABASE_URL) {
    pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dmj_entitlements (
        customer_id TEXT PRIMARY KEY,
        email TEXT,
        invoice_id TEXT UNIQUE,
        amount NUMERIC,
        currency TEXT,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS dmj_entitlements_email_idx ON dmj_entitlements ((lower(email)));
      CREATE INDEX IF NOT EXISTS dmj_entitlements_invoice_idx ON dmj_entitlements (invoice_id);
    `);
  }
})().catch(e => console.error('DB init error', e));

// --- Helpers ---
function uaHash(ua) {
  return crypto.createHash('sha256').update(String(ua || '')).digest('hex');
}

function signAuthCookie(res, payload) {
  // Use Lax for first-party (when COOKIE_DOMAIN like .dearmaryj.com is set),
  // fall back to None for cross-site (Railway default domain).
  const sameSite = process.env.COOKIE_SAMESITE || (COOKIE_DOMAIN ? 'lax' : 'none');
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1095d' }); // ~3 years
  const cookieOpts = {
    httpOnly: true,
    secure: COOKIE_SECURE === 'true',
    sameSite,
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

/**
 * IMPORTANT: BTCPay webhook must receive the RAW body.
 * We register the webhook route BEFORE express.json(), and use bodyParser.raw().
 */
app.post('/webhooks/btcpay', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  let payload;
  let event;

  try {
    // Verify webhook signature if secret is configured
    const signature = req.headers['btcpay-sig'];
    if (BTCPAY_WEBHOOK_SECRET) {
      const isValid = btcpayApi.verifyWebhookSignature(req.body.toString(), signature);
      if (!isValid) {
        console.error('Webhook signature verification failed');
        return res.status(400).send('Invalid signature');
      }
    }

    // Parse the webhook payload
    payload = JSON.parse(req.body.toString());
    event = payload;
  } catch (err) {
    console.error('Webhook parsing error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    // BTCPay webhook event types: InvoiceCreated, InvoiceReceivedPayment, 
    // InvoiceProcessing, InvoiceExpired, InvoiceSettled, InvoiceInvalid
    
    if (event.type === 'InvoiceSettled' || event.type === 'InvoiceProcessing') {
      // Invoice has been paid and confirmed (Settled) or is processing
      const invoiceId = event.invoiceId;
      
      // Fetch full invoice details
      const invoice = await btcpayApi.getInvoice(invoiceId);
      
      // Verify invoice status and amount
      if (invoice.status !== 'Settled' && invoice.status !== 'Processing') {
        console.log(`Invoice ${invoiceId} not settled/processing, skipping`);
        return res.json({ received: true });
      }

      // Extract metadata (email, customer_id, etc.)
      const metadata = invoice.metadata || {};
      const email = metadata.buyerEmail || metadata.email || null;
      const customerId = metadata.customerId || `invoice:${invoiceId}`;

      // Store entitlement in database
      if (pool) {
        await pool.query(`
          INSERT INTO dmj_entitlements (customer_id, email, invoice_id, amount, currency, active)
          VALUES ($1, $2, $3, $4, $5, TRUE)
          ON CONFLICT (customer_id) DO UPDATE SET
            email = EXCLUDED.email,
            invoice_id = EXCLUDED.invoice_id,
            amount = EXCLUDED.amount,
            currency = EXCLUDED.currency,
            active = TRUE,
            updated_at = now();
        `, [customerId, email, invoiceId, invoice.amount, invoice.currency]);
        
        console.log(`Entitlement stored for invoice ${invoiceId}, customer ${customerId}`);
      }
    } else if (event.type === 'InvoiceExpired' || event.type === 'InvoiceInvalid') {
      console.log(`Invoice ${event.invoiceId} expired or invalid`);
    }

    res.json({ received: true });
  } catch (e) {
    console.error('Webhook handler error', e);
    res.status(500).send('Webhook handler error');
  }
});

// AFTER the webhook route, it's safe to parse JSON for normal API routes
app.use(express.json());

// --- Routes ---
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Create BTCPay invoice and return checkout URL
app.post('/api/pay', async (req, res) => {
  try {
    const { email, customerId } = req.body || {};
    console.log('📝 /api/pay called with:', { email, customerId });
    
    // Create invoice on BTCPay Server
    const invoice = await btcpayApi.createInvoice({
      amount: BTCPAY_PAYMENT_AMOUNT,
      currency: BTCPAY_CURRENCY,
      metadata: {
        buyerEmail: email || undefined,
        customerId: customerId || undefined,
        orderId: `dmj-${Date.now()}`,
        itemDesc: 'Dear Mary J Subscription',
      },
      checkout: {
        redirectURL: `${allowedOrigins[0]}/payment-success?invoice_id={InvoiceId}`,
        redirectAutomatically: true,
        defaultLanguage: 'en-US',
      },
    });

    // Return the checkout URL to the client
    res.json({
      checkoutUrl: invoice.checkoutLink,
      invoiceId: invoice.id,
    });
  } catch (error) {
    console.error('Create invoice error:', error);
    res.status(500).json({ error: 'Failed to create invoice' });
  }
});

// Client checks if already unlocked (cookie)
app.get('/api/auth/status', (req, res) => {
  res.json({ unlocked: verifyAuth(req) });
});

// Validate BTCPay invoice on return from success
app.post('/api/validate-invoice', validateLimiter, async (req, res) => {
  try {
    const { invoice_id } = req.body || {};
    if (!invoice_id) return res.status(400).json({ error: 'Missing invoice_id' });

    // Verify with BTCPay Server
    const invoice = await btcpayApi.getInvoice(invoice_id);
    if (!invoice) return res.status(400).json({ error: 'Invalid invoice' });

    // Check if invoice is paid
    const isPaid = invoice.status === 'Settled' || invoice.status === 'Processing';
    if (!isPaid) {
      return res.status(402).json({ 
        error: 'Payment not completed', 
        status: invoice.status 
      });
    }

    // Verify amount matches expected amount
    const expectedAmount = parseFloat(BTCPAY_PAYMENT_AMOUNT);
    const invoiceAmount = parseFloat(invoice.amount);
    if (Math.abs(invoiceAmount - expectedAmount) > 0.01) {
      return res.status(400).json({ error: 'Unexpected amount' });
    }

    // Extract metadata
    const metadata = invoice.metadata || {};
    const email = metadata.buyerEmail || metadata.email || null;
    const customerId = metadata.customerId || `invoice:${invoice_id}`;

    // Persist entitlement (optional but recommended)
    if (pool) {
      try {
        await pool.query(`
          INSERT INTO dmj_entitlements (customer_id, email, invoice_id, amount, currency, active)
          VALUES ($1, $2, $3, $4, $5, TRUE)
          ON CONFLICT (customer_id) DO UPDATE SET
            email = EXCLUDED.email,
            invoice_id = EXCLUDED.invoice_id,
            amount = EXCLUDED.amount,
            currency = EXCLUDED.currency,
            active = TRUE,
            updated_at = now();
        `, [customerId, email, invoice_id, invoice.amount, invoice.currency]);
      } catch (dbErr) {
        console.error('DB upsert error', dbErr);
      }
    }

    // Issue long-lived HttpOnly cookie (lightly bound to UA)
    const uah = uaHash(req.headers['user-agent']);
    signAuthCookie(res, { sub: `invoice:${invoice_id}`, scope: 'unlocked', uah });

    res.json({ unlocked: true });
  } catch (err) {
    console.error('validate-invoice error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Restore across devices by email (requires DATABASE_URL + webhook/validate-invoice persistence)
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

// Optional logout helper
app.post('/api/logout', (req, res) => { clearAuthCookie(res); res.json({ ok: true }); });

// --- Subscription Management Endpoints ---

/**
 * Get subscription status for a customer
 * This checks if a customer has an active entitlement
 */
app.get('/api/subscription/status', async (req, res) => {
  try {
    if (!verifyAuth(req)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = req.cookies?.[COOKIE_NAME];
    const decoded = jwt.verify(token, JWT_SECRET);
    const customerId = decoded.sub;

    if (!pool) {
      return res.json({ active: true }); // If no DB, assume active based on cookie
    }

    const result = await pool.query(
      `SELECT active, created_at, updated_at FROM dmj_entitlements WHERE customer_id = $1`,
      [customerId.replace(/^(invoice:|restore:|checkout:)/, '')]
    );

    if (result.rows.length === 0) {
      return res.json({ active: false });
    }

    res.json({
      active: result.rows[0].active,
      since: result.rows[0].created_at,
      lastUpdated: result.rows[0].updated_at,
    });
  } catch (e) {
    console.error('subscription status error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * Cancel subscription
 * Since BTCPay doesn't have recurring subscriptions, this just marks the entitlement as inactive
 */
app.post('/api/subscription/cancel', async (req, res) => {
  try {
    if (!verifyAuth(req)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = req.cookies?.[COOKIE_NAME];
    const decoded = jwt.verify(token, JWT_SECRET);
    const customerId = decoded.sub;

    if (!pool) {
      // If no DB, just clear the cookie
      clearAuthCookie(res);
      return res.json({ success: true, message: 'Access revoked' });
    }

    await pool.query(
      `UPDATE dmj_entitlements SET active = FALSE, updated_at = now() WHERE customer_id = $1`,
      [customerId.replace(/^(invoice:|restore:|checkout:)/, '')]
    );

    clearAuthCookie(res);
    res.json({ success: true, message: 'Subscription cancelled' });
  } catch (e) {
    console.error('subscription cancel error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => console.log(`DMJ backend running on :${PORT} (BTCPay Server integration)`));

