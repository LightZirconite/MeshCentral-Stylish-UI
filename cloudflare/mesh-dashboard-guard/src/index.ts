type BanRecord = {
  key: string;
  type: "visitor" | "browser" | "network";
  reason: "non_fr_dashboard_access";
  firstSeenAt: string;
  lastSeenAt: string;
  firstCountry: string;
  lastCountry: string;
  ipPrefixHash: string;
  userAgentHash: string;
  path: string;
  expiresAt: string;
};

type CandidateIdentity = {
  key: string;
  type: BanRecord["type"];
};

type ExistingBan = CandidateIdentity & {
  record: BanRecord | null;
};

type BanGroup = {
  id: string;
  keys: string[];
  types: BanRecord["type"][];
  firstSeenAt: string;
  lastSeenAt: string;
  firstCountry: string;
  lastCountry: string;
  ipPrefixHash: string;
  userAgentHash: string;
  path: string;
  expiresAt: string;
};

const COOKIE_NAME = "meshguard_id";
const PASS_COOKIE_NAME = "meshguard_fr_ok";
const ADMIN_COOKIE_NAME = "meshguard_admin";
const ADMIN_SESSION_SECONDS = 12 * 60 * 60;
const DEFAULT_ALLOWED_COUNTRY = "FR";
const DEFAULT_BAN_TTL_SECONDS = 90 * 24 * 60 * 60;
const DEFAULT_PASS_TTL_SECONDS = 2 * 60 * 60;
const DEFAULT_BAN_TOUCH_INTERVAL_SECONDS = 15 * 60;
const MAX_ADMIN_LIST = 500;
const MAX_GROUP_DELETE_KEYS = 16;

const AGENT_PATHS = new Set([
  "/agent.ashx",
  "/meshrelay.ashx",
  "/meshagents",
  "/meshsettings",
  "/control.ashx",
  "/amtevents.ashx"
]);

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await handleRequest(request, env, ctx);
    } catch (error) {
      console.error(JSON.stringify({
        message: "meshguard_unhandled_error",
        error: error instanceof Error ? error.message : String(error),
        path: new URL(request.url).pathname
      }));
      return notFound();
    }
  }
} satisfies ExportedHandler<Env>;

async function handleRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const adminPath = env.ADMIN_PATH || "/__meshguard/admin";

  if (isAdminPath(url.pathname, adminPath)) {
    return handleAdmin(request, env, url, adminPath);
  }

  if (isAgentRequest(url.pathname)) {
    return fetch(request);
  }

  const country = getCountry(request);
  const allowedCountry = (env.ALLOWED_COUNTRY || DEFAULT_ALLOWED_COUNTRY).toUpperCase();
  const banTtlSeconds = parsePositiveInt(env.BAN_TTL_SECONDS, DEFAULT_BAN_TTL_SECONDS);
  const passTtlSeconds = parsePositiveInt(env.PASS_TTL_SECONDS, DEFAULT_PASS_TTL_SECONDS);
  const banTouchIntervalSeconds = parsePositiveInt(env.BAN_TOUCH_INTERVAL_SECONDS, DEFAULT_BAN_TOUCH_INTERVAL_SECONDS);
  const cookies = parseCookies(request.headers.get("Cookie"));
  const validCookieId = await verifySignedValue(cookies.get(COOKIE_NAME), env.MESHGUARD_COOKIE_SECRET);

  if (
    country === allowedCountry &&
    !validCookieId &&
    await verifyPassCookie(cookies.get(PASS_COOKIE_NAME), request, env)
  ) {
    return fetch(request);
  }

  const candidateKeys = await buildCandidateIdentities(request, env, validCookieId);
  const existingBan = await firstExistingBan(env, candidateKeys);

  if (existingBan) {
    ctx.waitUntil(touchBan(env, existingBan, country, banTouchIntervalSeconds));
    return notFound();
  }

  if (country !== allowedCountry) {
    const issuedCookieId = validCookieId || crypto.randomUUID();
    const issuedCookie = await signCookie(COOKIE_NAME, issuedCookieId, env.MESHGUARD_COOKIE_SECRET, banTtlSeconds);
    const identities = await buildCandidateIdentities(request, env, issuedCookieId);
    const now = new Date();
    const headers = new Headers(notFoundHeaders());
    headers.append("Set-Cookie", issuedCookie);
    headers.append("Set-Cookie", expireCookie(PASS_COOKIE_NAME));

    ctx.waitUntil(storeBans(env, identities, request, country, url.pathname, banTtlSeconds, now));
    console.log(JSON.stringify({
      message: "meshguard_blocked_country",
      country,
      path: url.pathname,
      identityCount: identities.length
    }));
    return new Response("", { status: 404, headers });
  }

  const response = await fetch(request);
  if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") return response;

  const passValue = await buildPassValue(request, env, passTtlSeconds);
  const passCookie = await signCookie(PASS_COOKIE_NAME, passValue, env.MESHGUARD_COOKIE_SECRET, passTtlSeconds);
  return appendSetCookie(response, passCookie);
}

function isAgentRequest(pathname: string): boolean {
  const path = pathname.toLowerCase();
  return AGENT_PATHS.has(path);
}

function isAdminPath(pathname: string, adminPath: string): boolean {
  return pathname === adminPath || pathname.startsWith(`${adminPath}/`);
}

function getCountry(request: Request): string {
  const cf = request.cf as IncomingRequestCfProperties | undefined;
  const country = typeof cf?.country === "string" ? cf.country : "";
  return country.toUpperCase() || "XX";
}

async function buildCandidateIdentities(request: Request, env: Env, visitorId: string | null): Promise<CandidateIdentity[]> {
  const identities: CandidateIdentity[] = [];
  const fingerprint = getBrowserFingerprint(request);
  const networkFingerprint = `${getIpPrefix(request)}|${fingerprint}`;

  if (visitorId) {
    identities.push({ type: "visitor", key: await banKey(env, "visitor", visitorId) });
  }

  identities.push({ type: "browser", key: await banKey(env, "browser", fingerprint) });
  identities.push({ type: "network", key: await banKey(env, "network", networkFingerprint) });

  return identities;
}

async function firstExistingBan(env: Env, identities: CandidateIdentity[]): Promise<ExistingBan | null> {
  for (const identity of identities) {
    const value = await env.MESHGUARD_BANS.get(identity.key);
    if (value !== null) return { ...identity, record: parseBanRecord(identity.key, value) };
  }
  return null;
}

async function storeBans(
  env: Env,
  identities: CandidateIdentity[],
  request: Request,
  country: string,
  path: string,
  ttlSeconds: number,
  now: Date
): Promise<void> {
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
  const ipPrefixHash = await hashText(env, getIpPrefix(request));
  const userAgentHash = await hashText(env, request.headers.get("User-Agent") || "");

  await Promise.all(identities.map((identity) => {
    const record: BanRecord = {
      key: identity.key,
      type: identity.type,
      reason: "non_fr_dashboard_access",
      firstSeenAt: now.toISOString(),
      lastSeenAt: now.toISOString(),
      firstCountry: country,
      lastCountry: country,
      ipPrefixHash,
      userAgentHash,
      path,
      expiresAt
    };
    return env.MESHGUARD_BANS.put(identity.key, JSON.stringify(record), { expirationTtl: ttlSeconds });
  }));
}

async function touchBan(env: Env, ban: ExistingBan, country: string, minIntervalSeconds: number): Promise<void> {
  if (!ban.record) return;

  try {
    const record = ban.record;
    const lastSeen = Date.parse(record.lastSeenAt);
    if (Number.isFinite(lastSeen) && Date.now() - lastSeen < minIntervalSeconds * 1000) return;

    record.lastSeenAt = new Date().toISOString();
    record.lastCountry = country;
    const remainingSeconds = Math.max(60, Math.floor((Date.parse(record.expiresAt) - Date.now()) / 1000));
    await env.MESHGUARD_BANS.put(ban.key, JSON.stringify(record), { expirationTtl: remainingSeconds });
  } catch (error) {
    console.error(JSON.stringify({
      message: "meshguard_touch_ban_failed",
      key: ban.key,
      error: error instanceof Error ? error.message : String(error)
    }));
  }
}

async function handleAdmin(request: Request, env: Env, url: URL, adminPath: string): Promise<Response> {
  const country = getCountry(request);
  const allowedCountry = (env.ALLOWED_COUNTRY || DEFAULT_ALLOWED_COUNTRY).toUpperCase();
  if (country !== allowedCountry) return notFound();

  const cookies = parseCookies(request.headers.get("Cookie"));
  const adminSession = await verifySignedValue(cookies.get(ADMIN_COOKIE_NAME), env.MESHGUARD_ADMIN_SECRET);
  const csrf = adminSession ? await hmacHex(env.MESHGUARD_ADMIN_SECRET, `csrf:${adminSession}`) : "";

  if (url.pathname === `${adminPath}/login` && request.method === "POST") {
    const form = await request.formData();
    const suppliedSecret = stringFormValue(form.get("secret"));
    if (!(await safeEqual(suppliedSecret, env.MESHGUARD_ADMIN_SECRET))) {
      return html(loginPage(adminPath, true), 403);
    }

    const sessionId = crypto.randomUUID();
    const sessionCookie = await signCookie(ADMIN_COOKIE_NAME, sessionId, env.MESHGUARD_ADMIN_SECRET, ADMIN_SESSION_SECONDS);
    return redirect(adminPath, sessionCookie);
  }

  if (!adminSession) {
    return html(loginPage(adminPath, false), 200);
  }

  if (request.method === "POST" && url.pathname === `${adminPath}/unban`) {
    const form = await request.formData();
    const formCsrf = stringFormValue(form.get("csrf"));
    if (!(await safeEqual(formCsrf, csrf))) return notFound();

    const keys = form.getAll("key")
      .map(stringFormValue)
      .filter((key) => key.startsWith("ban:"))
      .slice(0, MAX_GROUP_DELETE_KEYS);
    const uniqueKeys = Array.from(new Set(keys));

    await Promise.all(uniqueKeys.map((key) => env.MESHGUARD_BANS.delete(key)));
    if (uniqueKeys.length > 0) {
      console.log(JSON.stringify({ message: "meshguard_admin_unban", count: uniqueKeys.length }));
    }

    const query = stringFormValue(form.get("q"));
    return redirect(query ? `${adminPath}?q=${encodeURIComponent(query)}` : adminPath);
  }

  if (request.method !== "GET" || url.pathname !== adminPath) return notFound();

  const query = (url.searchParams.get("q") || "").trim();
  const bans = await listBanRecords(env);
  const groups = await filterBanGroups(env, groupBanRecords(bans), query);
  return html(adminPage(adminPath, groups, csrf, query), 200);
}

async function listBanRecords(env: Env): Promise<BanRecord[]> {
  const listed = await env.MESHGUARD_BANS.list({ prefix: "ban:", limit: MAX_ADMIN_LIST });
  const records: BanRecord[] = [];

  for (const key of listed.keys) {
    const raw = await env.MESHGUARD_BANS.get(key.name);
    if (!raw) continue;
    const record = parseBanRecord(key.name, raw);
    if (record) {
      records.push(record);
    } else {
      records.push({
        key: key.name,
        type: "visitor",
        reason: "non_fr_dashboard_access",
        firstSeenAt: "",
        lastSeenAt: "",
        firstCountry: "",
        lastCountry: "",
        ipPrefixHash: "",
        userAgentHash: "",
        path: "",
        expiresAt: ""
      });
    }
  }

  return records.sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
}

function groupBanRecords(records: BanRecord[]): BanGroup[] {
  const groups = new Map<string, BanGroup>();

  for (const record of records) {
    const groupKey = `${record.ipPrefixHash}|${record.userAgentHash}|${record.expiresAt}`;
    const existing = groups.get(groupKey);

    if (!existing) {
      groups.set(groupKey, {
        id: `${record.ipPrefixHash.slice(0, 12)}:${record.userAgentHash.slice(0, 12)}:${record.expiresAt}`,
        keys: [record.key],
        types: [record.type],
        firstSeenAt: record.firstSeenAt,
        lastSeenAt: record.lastSeenAt,
        firstCountry: record.firstCountry,
        lastCountry: record.lastCountry,
        ipPrefixHash: record.ipPrefixHash,
        userAgentHash: record.userAgentHash,
        path: record.path,
        expiresAt: record.expiresAt
      });
      continue;
    }

    existing.keys.push(record.key);
    if (!existing.types.includes(record.type)) existing.types.push(record.type);
    if (record.firstSeenAt && (!existing.firstSeenAt || record.firstSeenAt < existing.firstSeenAt)) {
      existing.firstSeenAt = record.firstSeenAt;
    }
    if (record.lastSeenAt > existing.lastSeenAt) {
      existing.lastSeenAt = record.lastSeenAt;
      existing.lastCountry = record.lastCountry;
    }
    if (!existing.path && record.path) existing.path = record.path;
  }

  return Array.from(groups.values()).sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
}

async function filterBanGroups(env: Env, groups: BanGroup[], query: string): Promise<BanGroup[]> {
  const q = query.trim().toLowerCase();
  if (!q) return groups;

  const ipPrefix = normalizeSearchIpPrefix(q);
  const searchedIpHash = ipPrefix ? await hashText(env, ipPrefix) : "";

  return groups.filter((group) => {
    const haystack = [
      group.id,
      group.keys.join(" "),
      group.types.join(" "),
      group.firstCountry,
      group.lastCountry,
      group.path,
      group.expiresAt,
      group.ipPrefixHash,
      group.userAgentHash
    ].join(" ").toLowerCase();

    return haystack.includes(q) || (searchedIpHash !== "" && group.ipPrefixHash === searchedIpHash);
  });
}

function normalizeSearchIpPrefix(query: string): string {
  const token = query.trim().split(/\s+/)[0].replace(/^\[/, "").replace(/\]$/, "");
  const ipv4 = token.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\.\d{1,3})?(?:\/\d{1,2})?$/);
  if (ipv4) return `${ipv4[1]}.${ipv4[2]}.${ipv4[3]}`;

  if (token.includes(":")) {
    const hextets = token.split(":").filter(Boolean);
    if (hextets.length >= 4) return hextets.slice(0, 4).join(":").toLowerCase();
  }

  return "";
}

function parseBanRecord(key: string, raw: string): BanRecord | null {
  try {
    const record = JSON.parse(raw) as Partial<BanRecord>;
    if (!record || typeof record !== "object") return null;
    return {
      key,
      type: record.type === "browser" || record.type === "network" ? record.type : "visitor",
      reason: "non_fr_dashboard_access",
      firstSeenAt: typeof record.firstSeenAt === "string" ? record.firstSeenAt : "",
      lastSeenAt: typeof record.lastSeenAt === "string" ? record.lastSeenAt : "",
      firstCountry: typeof record.firstCountry === "string" ? record.firstCountry : "",
      lastCountry: typeof record.lastCountry === "string" ? record.lastCountry : "",
      ipPrefixHash: typeof record.ipPrefixHash === "string" ? record.ipPrefixHash : "",
      userAgentHash: typeof record.userAgentHash === "string" ? record.userAgentHash : "",
      path: typeof record.path === "string" ? record.path : "",
      expiresAt: typeof record.expiresAt === "string" ? record.expiresAt : ""
    };
  } catch {
    return null;
  }
}

async function buildPassValue(request: Request, env: Env, ttlSeconds: number): Promise<string> {
  const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
  const [ipHash, browserHash] = await Promise.all([
    hashText(env, getIpPrefix(request)),
    hashText(env, getBrowserFingerprint(request))
  ]);
  return `v1:${expiresAt}:${ipHash}:${browserHash}`;
}

async function verifyPassCookie(raw: string | undefined, request: Request, env: Env): Promise<boolean> {
  const value = await verifySignedValue(raw, env.MESHGUARD_COOKIE_SECRET);
  if (!value) return false;

  const parts = value.split(":");
  if (parts.length !== 4 || parts[0] !== "v1") return false;

  const expiresAt = Number.parseInt(parts[1], 10);
  if (!Number.isFinite(expiresAt) || expiresAt <= Math.floor(Date.now() / 1000)) return false;

  const [ipHash, browserHash] = await Promise.all([
    hashText(env, getIpPrefix(request)),
    hashText(env, getBrowserFingerprint(request))
  ]);

  return await safeEqual(ipHash, parts[2]) && await safeEqual(browserHash, parts[3]);
}

async function banKey(env: Env, type: BanRecord["type"], value: string): Promise<string> {
  return `ban:${type}:${await hmacHex(env.MESHGUARD_COOKIE_SECRET, `${type}:${value}`)}`;
}

function getBrowserFingerprint(request: Request): string {
  const headers = request.headers;
  return [
    normalizeHeader(headers.get("User-Agent")),
    normalizeHeader(headers.get("Accept-Language")),
    normalizeHeader(headers.get("Sec-CH-UA")),
    normalizeHeader(headers.get("Sec-CH-UA-Platform")),
    normalizeHeader(headers.get("Sec-CH-UA-Mobile"))
  ].join("|");
}

function getIpPrefix(request: Request): string {
  const ip = request.headers.get("CF-Connecting-IP") || "";
  if (ip.includes(".")) return ip.split(".").slice(0, 3).join(".");
  if (ip.includes(":")) return ip.split(":").slice(0, 4).join(":").toLowerCase();
  return ip;
}

function normalizeHeader(value: string | null): string {
  return (value || "").replace(/\s+/g, " ").trim().toLowerCase().slice(0, 512);
}

async function signCookie(name: string, value: string, secret: string, maxAgeSeconds: number): Promise<string> {
  const signed = `${value}.${await hmacBase64Url(secret, value)}`;
  return `${name}=${signed}; Max-Age=${maxAgeSeconds}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

function expireCookie(name: string): string {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

function appendSetCookie(response: Response, cookie: string): Response {
  const headers = new Headers(response.headers);
  headers.append("Set-Cookie", cookie);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

async function verifySignedValue(raw: string | undefined, secret: string): Promise<string | null> {
  if (!raw) return null;

  const separator = raw.lastIndexOf(".");
  if (separator <= 0) return null;

  const value = raw.slice(0, separator);
  const signature = raw.slice(separator + 1);
  const expected = await hmacBase64Url(secret, value);
  return await safeEqual(signature, expected) ? value : null;
}

async function hmacBase64Url(secret: string, value: string): Promise<string> {
  const bytes = new Uint8Array(await hmac(secret, value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hmacHex(secret: string, value: string): Promise<string> {
  const bytes = new Uint8Array(await hmac(secret, value));
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmac(secret: string, value: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", key, encoder.encode(value));
}

async function hashText(env: Env, value: string): Promise<string> {
  return hmacHex(env.MESHGUARD_COOKIE_SECRET, `hash:${value}`);
}

async function safeEqual(left: string, right: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right))
  ]);
  const a = new Uint8Array(leftHash);
  const b = new Uint8Array(rightHash);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    diff |= (a[i] || 0) ^ (b[i] || 0);
  }
  return diff === 0;
}

function parseCookies(header: string | null): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!header) return cookies;

  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    cookies.set(name, value);
  }

  return cookies;
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function notFound(): Response {
  return new Response("", { status: 404, headers: notFoundHeaders() });
}

function notFoundHeaders(): HeadersInit {
  return {
    "Cache-Control": "no-store",
    "Content-Type": "text/plain; charset=utf-8",
    "X-Robots-Tag": "noindex, nofollow"
  };
}

function html(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "text/html; charset=utf-8",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer"
    }
  });
}

function redirect(location: string, cookie?: string): Response {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Location": location
  });
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response("", { status: 303, headers });
}

function loginPage(adminPath: string, failed: boolean): string {
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MeshGuard Admin</title>
  <style>
    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f172a;color:#e5e7eb;font:14px system-ui,sans-serif}
    form{width:min(360px,calc(100vw - 32px));display:grid;gap:12px}
    input,button{height:40px;border-radius:6px;border:1px solid #334155;background:#111827;color:#e5e7eb;padding:0 12px}
    button{background:#2563eb;border-color:#2563eb;font-weight:700;cursor:pointer}
    p{margin:0;color:#fca5a5}
    .sr-only{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}
  </style>
</head>
<body>
  <form method="post" action="${escapeHtml(adminPath)}/login">
    ${failed ? "<p>Secret invalide.</p>" : ""}
    <input class="sr-only" type="text" name="username" value="meshguard-admin" autocomplete="username" tabindex="-1" aria-hidden="true">
    <input type="password" name="secret" autocomplete="current-password" placeholder="Secret admin" required autofocus>
    <button type="submit">Connexion</button>
  </form>
</body>
</html>`;
}

function adminPage(adminPath: string, groups: BanGroup[], csrf: string, query: string): string {
  const rows = groups.map((group) => `<tr>
    <td>
      <strong>${escapeHtml(group.types.join(" + "))}</strong>
      <div class="muted">${group.keys.length} cle${group.keys.length > 1 ? "s" : ""}</div>
    </td>
    <td>${escapeHtml(group.firstCountry)} -> ${escapeHtml(group.lastCountry)}</td>
    <td>${escapeHtml(group.path || "/")}</td>
    <td>${escapeHtml(group.lastSeenAt)}</td>
    <td>${escapeHtml(group.expiresAt)}</td>
    <td>
      <code>ip:${escapeHtml(group.ipPrefixHash.slice(0, 18))}</code><br>
      <code>ua:${escapeHtml(group.userAgentHash.slice(0, 18))}</code>
      <details>
        <summary>Voir les cles</summary>
        ${group.keys.map((key) => `<code>${escapeHtml(key)}</code>`).join("<br>")}
      </details>
    </td>
    <td>
      <form method="post" action="${escapeHtml(adminPath)}/unban">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <input type="hidden" name="q" value="${escapeHtml(query)}">
        ${group.keys.map((key) => `<input type="hidden" name="key" value="${escapeHtml(key)}">`).join("")}
        <button type="submit">Debannir</button>
      </form>
    </td>
  </tr>`).join("");

  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MeshGuard Bans</title>
  <style>
    body{margin:0;background:#f8fafc;color:#111827;font:13px system-ui,sans-serif}
    main{padding:24px;max-width:1280px;margin:0 auto}
    header{display:flex;gap:16px;align-items:flex-end;justify-content:space-between;margin:0 0 16px}
    h1{font-size:20px;margin:0}
    .search{display:flex;gap:8px;align-items:center}
    .search input{height:34px;width:min(360px,52vw);border-radius:6px;border:1px solid #cbd5e1;background:white;color:#111827;padding:0 10px}
    table{width:100%;border-collapse:collapse;background:white;border:1px solid #e5e7eb}
    th,td{padding:9px 10px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}
    th{background:#f1f5f9;font-size:12px;text-transform:uppercase;color:#475569}
    code{font-size:11px;word-break:break-all}
    button,.linkbutton{height:30px;border-radius:6px;border:1px solid #dc2626;background:#dc2626;color:white;font-weight:700;cursor:pointer;padding:0 10px}
    .search button,.linkbutton{border-color:#334155;background:#334155;text-decoration:none;display:inline-grid;place-items:center}
    .empty{padding:18px;background:white;border:1px solid #e5e7eb}
    .muted{color:#64748b;font-size:12px;margin-top:3px}
    details{margin-top:6px}
    summary{cursor:pointer;color:#334155}
    @media(max-width:720px){main{padding:14px}header{display:grid}.search{display:grid;grid-template-columns:1fr auto}.search input{width:auto}table{font-size:12px}}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>MeshGuard Bans</h1>
      <form class="search" method="get" action="${escapeHtml(adminPath)}">
        <input type="search" name="q" value="${escapeHtml(query)}" autocomplete="off" placeholder="IP, pays, hash ou chemin">
        <button type="submit">Rechercher</button>
        ${query ? `<a class="linkbutton" href="${escapeHtml(adminPath)}">Reset</a>` : ""}
      </form>
    </header>
    ${groups.length === 0 ? '<div class="empty">Aucun ban actif ou aucun resultat.</div>' : `<table>
      <thead><tr><th>Identite</th><th>Pays</th><th>Chemin</th><th>Dernier acces</th><th>Expire</th><th>Hashes</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`}
  </main>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stringFormValue(value: FormDataEntryValue | null): string {
  return typeof value === "string" ? value : "";
}
