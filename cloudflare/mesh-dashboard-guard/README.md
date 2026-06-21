# Mesh Dashboard Guard

Cloudflare Worker for `mesh.lgtw.tf/*`.

It returns a blank `404` for browser/dashboard traffic outside France, stores a 90 day ban, and still lets MeshCentral agent endpoints pass through globally.

This directory is only source code until the Worker is deployed on the Cloudflare account that owns `lgtw.tf`. If `wrangler whoami` says you are not authenticated, the production domain is not protected yet and VPN traffic will still reach MeshCentral normally.

## Cost and latency guardrails

- MeshCentral agent endpoints return to the origin immediately and do not use KV or crypto.
- A signed `meshguard_fr_ok` pass cookie lets already-validated France dashboard traffic skip KV reads for `PASS_TTL_SECONDS` seconds.
- Active bans are only touched every `BAN_TOUCH_INTERVAL_SECONDS` seconds to avoid one KV write per spammed request.
- For the lowest possible agent overhead, create more-specific Cloudflare routes without a Worker script for agent paths. Cloudflare route matching lets a more-specific no-script route negate the broader `mesh.lgtw.tf/*` Worker route.

Current no-script bypass candidates:

```text
mesh.lgtw.tf/agent.ashx*
mesh.lgtw.tf/meshrelay.ashx*
mesh.lgtw.tf/meshagents*
mesh.lgtw.tf/meshsettings*
mesh.lgtw.tf/control.ashx*
mesh.lgtw.tf/amtevents.ashx*
```

## Deploy

1. Authenticate Wrangler on the production Cloudflare account:

   ```powershell
   npx wrangler login
   npx wrangler whoami
   ```

2. Create the KV namespace:

   ```powershell
   npx wrangler kv namespace create MESHGUARD_BANS
   npx wrangler kv namespace create MESHGUARD_BANS --preview
   ```

3. Replace the placeholder IDs in `wrangler.jsonc`.

4. Set secrets:

   ```powershell
   npx wrangler secret put MESHGUARD_COOKIE_SECRET
   npx wrangler secret put MESHGUARD_ADMIN_SECRET
   ```

5. Validate and deploy:

   ```powershell
   npm install
   npm run check
   npx wrangler deploy
   ```

6. Verify the live route:

   ```powershell
   curl.exe -I https://mesh.lgtw.tf/
   ```

   Test from a non-FR IP should return `404` with an empty body. Test from France should continue to load the dashboard unless the same browser was already banned.

## Admin

Open `https://mesh.lgtw.tf/__meshguard/admin` from France. Log in with `MESHGUARD_ADMIN_SECRET`, then delete ban entries as needed.

The browser can save the admin secret as a password for the `meshguard-admin` username. The admin session cookie lasts 12 hours.

The Worker stores only HMAC-derived keys and coarse request metadata. It does not store raw IP addresses or raw browser fingerprints. IP search works by hashing the searched IP prefix with the same secret and comparing it to the stored HMAC.
