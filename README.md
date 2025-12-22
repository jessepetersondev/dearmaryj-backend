# Dear Mary J — Secure Paywall Backend (BTCPay Server + Express)

This backend secures access to your static journal app using **BTCPay Server invoices** and an **HttpOnly, signed cookie**. No existing front-end features are removed; a top-layer overlay simply blocks interaction until payment is verified.

> **🚀 Quick Start:** Deploy to Railway? See **[RAILWAY_DEPLOYMENT.md](./RAILWAY_DEPLOYMENT.md)** for step-by-step deployment instructions.

> **📖 Full Setup:** For complete BTCPay Server configuration and hosting options, see [BTCPAY_SETUP.md](./BTCPAY_SETUP.md).

> **🔄 Migrating from Stripe?** See [MIGRATION_GUIDE.md](./MIGRATION_GUIDE.md) for migration instructions.

## How it works
1. User clicks **Unlock** → front-end calls `POST /api/pay` to create a BTCPay invoice.
2. Backend returns a `checkoutUrl` and `invoiceId`.
3. User is redirected to BTCPay checkout page to complete payment.
4. BTCPay redirects back to your **front-end** success URL with `?invoice_id={INVOICE_ID}`.
5. The front-end calls `POST /api/validate-invoice` with that `invoice_id`.
6. Backend verifies the invoice with BTCPay Server, checks payment status and amount, and **sets an HttpOnly cookie**.
7. Front-end calls `GET /api/auth/status` and hides the overlay once unlocked.

## Quick Start

**For detailed deployment instructions, see [RAILWAY_DEPLOYMENT.md](./RAILWAY_DEPLOYMENT.md)**

### Overview

1. **Deploy BTCPay Server** to a cloud/hosted environment (LunaNode recommended)
2. **Get credentials** from BTCPay (Store ID, API Key)
3. **Deploy backend** to Railway with environment variables
4. **Configure webhook** in BTCPay to notify your backend
5. **Update frontend** to use new payment endpoints

**⚠️ Important**: Do NOT run BTCPay Server locally. Use a cloud provider like LunaNode, VPS, or third-party hosting.

## Front-end Integration

Update your front-end to work with BTCPay Server:

```javascript
const DMJ_API_BASE = "https://your-railway-url".replace(/\/$/, "");

// Create invoice and redirect to checkout
async function unlockContent() {
  const response = await fetch(`${DMJ_API_BASE}/api/pay`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      email: userEmail, // optional
      customerId: userId // optional
    })
  });
  
  const { checkoutUrl } = await response.json();
  window.location.href = checkoutUrl; // Redirect to BTCPay checkout
}

// On success page, validate the invoice
async function validatePayment() {
  const params = new URLSearchParams(window.location.search);
  const invoiceId = params.get('invoice_id');
  
  if (invoiceId) {
    const response = await fetch(`${DMJ_API_BASE}/api/validate-invoice`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ invoice_id: invoiceId })
    });
    
    const { unlocked } = await response.json();
    if (unlocked) {
      // Remove overlay, user has access
    }
  }
}
```

**Key Changes from Stripe:**
- `/api/pay` is now POST (not GET redirect)
- Returns `checkoutUrl` and `invoiceId`
- Success page receives `invoice_id` parameter (not `session_id`)
- Use `/api/validate-invoice` endpoint (not `/api/validate-session`)

## API Endpoints

### Public Endpoints
- `GET /api/health` → Health check
- `POST /api/pay` → Create BTCPay invoice, returns `{ checkoutUrl, invoiceId }`
  - Optional body: `{ "email": "user@example.com", "customerId": "user123" }`
- `POST /api/validate-invoice` → Validate invoice and set auth cookie
  - Body: `{ "invoice_id": "..." }`
- `GET /api/auth/status` → Check authentication status
  - Returns: `{ "unlocked": true/false }`
- `POST /api/restore` → Restore access by email (requires DATABASE_URL)
  - Body: `{ "email": "user@example.com" }`
- `POST /api/logout` → Clear auth cookie

### Authenticated Endpoints
- `GET /api/subscription/status` → Get subscription details
- `POST /api/subscription/cancel` → Cancel subscription (mark as inactive)

### Webhook Endpoints
- `POST /webhooks/btcpay` → Receives BTCPay Server webhook events

## Security Notes
- Auth cookie is **HttpOnly**, **Secure**, **SameSite=Lax**, **signed (JWT)**, and lightly bound to the **User-Agent hash** to deter trivial cookie theft/replay.
- Invoice amount verification ensures only properly paid invoices unlock access.
- Webhook signature verification (when `BTCPAY_WEBHOOK_SECRET` is set) prevents spoofed webhook calls.
- Rate limiting on validation endpoints prevents brute-force attempts.
- Database persistence (when `DATABASE_URL` is set) enables cross-device access restoration.

## Documentation

For complete BTCPay Server setup instructions, troubleshooting, and API documentation, see [BTCPAY_SETUP.md](./BTCPAY_SETUP.md).

## Key Differences from Stripe

1. **Cloud/Hosted Deployment**: You must deploy BTCPay Server to a cloud provider (not run locally)
2. **Cryptocurrency**: Accepts Bitcoin and other cryptocurrencies instead of credit cards
3. **No recurring subscriptions**: Each payment requires a new invoice (implement renewal reminders)
4. **Lower fees**: No payment processor fees (only network transaction fees + hosting costs)
5. **More control**: Full control over payment processing and data
6. **Self-sovereign**: No third-party can freeze or reverse payments

## Migration from Stripe

If you're migrating from the previous Stripe implementation:

1. **Backend**: Replace with this updated `server.js`
2. **Environment Variables**: Update from `STRIPE_*` to `BTCPAY_*` variables
3. **Frontend**: Update payment flow to use POST `/api/pay` and `/api/validate-invoice`
4. **Success URL**: Change parameter from `session_id` to `invoice_id`
5. **Testing**: Test thoroughly with BTCPay testnet before going live

See [BTCPAY_SETUP.md](./BTCPAY_SETUP.md) for detailed migration instructions and examples.
