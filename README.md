# Dear Mary J — Secure Paywall Backend (Stripe + Express)

This backend secures access to your static journal app using **Stripe Payment Links** and an **HttpOnly, signed cookie**. No existing front-end features are removed; a top-layer overlay simply blocks interaction until payment is verified.

## How it works
1. User clicks **Unlock** → `/api/pay` redirects to your Stripe Payment Link (one-time $4.20 purchase).
2. Stripe redirects back to your **front-end** success URL with `?session_id={CHECKOUT_SESSION_ID}`.
3. The front-end calls `POST /api/validate-session` with that `session_id`.
4. Backend verifies the session with Stripe, checks `payment_status` and **Price ID**, and **sets an HttpOnly cookie**.
5. Front-end calls `GET /api/auth/status` and hides the overlay once unlocked.

## Deploy (Railway)
1. Create a new **Railway** project → **Node.js** service.
2. Add the following **Environment Variables** (from `.env.example`):
   - `STRIPE_SECRET_KEY`
   - `STRIPE_PAYMENT_LINK_URL`
   - `STRIPE_PRICE_ID`
   - `JWT_SECRET` (long random string)
   - `APP_DOMAIN_ORIGIN` (your GitHub Pages origin or custom domain where the front-end is hosted)
   - Optional: `COOKIE_DOMAIN`, `COOKIE_SECURE` (true on production HTTPS)
3. Deploy. Railway will expose a URL like `https://your-app.up.railway.app`.

## Configure your Stripe Payment Link
- In Stripe Dashboard, open your Payment Link.
- Under **Post-payment behavior** set **Redirect to your site** and **Success URL** to your app URL with `?session_id={CHECKOUT_SESSION_ID}`, e.g.  
  `https://your-gh-pages-domain/index.html?session_id={CHECKOUT_SESSION_ID}`
- Ensure the Payment Link is tied to the **Price** whose ID you put into `STRIPE_PRICE_ID` (for $4.20).

## Front-end wiring
- In your `index.html`, set:
  ```html
  const DMJ_API_BASE = "https://your-railway-url".replace(/\/$/, "");
  ```
- The overlay is inserted without touching your existing IDs or behavior. If you need to move the **Unlock** button somewhere else, simply link to:  
  `https://your-railway-url/api/pay`

## Endpoints
- `GET /api/pay` → 302 redirect to Stripe Payment Link
- `POST /api/validate-session` → body `{ "session_id": "cs_live_..." }`, sets cookie if valid
- `GET /api/auth/status` → `{ unlocked: true/false }`
- `POST /api/logout` → clears cookie

## Security Notes
- Auth cookie is **HttpOnly**, **Secure**, **SameSite=Lax**, **signed (JWT)**, and lightly bound to the **User-Agent hash** to deter trivial cookie theft/replay.
- Price verification ensures only the expected Payment Link’s price unlocks access.
- For stricter device binding or revocation, add a small database keyed by `sub` (session id) and issue per-device tokens with rotation.
