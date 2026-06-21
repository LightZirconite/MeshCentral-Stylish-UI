# Mesh Dashboard Guard

Cloudflare Worker for `mesh.lgtw.tf/*`.

It returns a blank `404` for browser/dashboard traffic outside France, stores a 90 day ban, and still lets MeshCentral agent endpoints pass through globally.

This directory is only source code until the Worker is deployed on the Cloudflare account that owns `lgtw.tf`. If `wrangler whoami` says you are not authenticated, the production domain is not protected yet and VPN traffic will still reach MeshCentral normally.

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

The Worker stores only HMAC-derived keys and coarse request metadata. It does not store raw IP addresses or raw browser fingerprints.
