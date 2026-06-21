# Mesh Dashboard Guard

Cloudflare Worker for `mesh.lgtw.tf/*`.

It returns a blank `404` for browser/dashboard traffic outside France, stores a 90 day ban, and still lets MeshCentral agent endpoints pass through globally.

## Deploy

1. Create the KV namespace:

   ```powershell
   npx wrangler kv namespace create MESHGUARD_BANS
   npx wrangler kv namespace create MESHGUARD_BANS --preview
   ```

2. Replace the placeholder IDs in `wrangler.jsonc`.

3. Set secrets:

   ```powershell
   npx wrangler secret put MESHGUARD_COOKIE_SECRET
   npx wrangler secret put MESHGUARD_ADMIN_SECRET
   ```

4. Validate and deploy:

   ```powershell
   npm install
   npm run check
   npx wrangler deploy
   ```

## Admin

Open `https://mesh.lgtw.tf/__meshguard/admin` from France. Log in with `MESHGUARD_ADMIN_SECRET`, then delete ban entries as needed.

The Worker stores only HMAC-derived keys and coarse request metadata. It does not store raw IP addresses or raw browser fingerprints.
