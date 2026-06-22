require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const db = require("./db");

void db.ready.catch((err) => {
  console.error("Database initialization failed:", err.message || err);
});

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "&mgmz7Ko2bJtLyD@6kP$!CNMjJKSsfcwMXHzny2rx5j&69yC8&JcwKSvxE6CVhT7";

app.set("trust proxy", true);

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));
app.use(async (req, res, next) => {
  try {
    await db.ready;
    return next();
  } catch (err) {
    console.error("Database initialization failed:", err);
    return res.status(500).json({ error: "Database initialization failed." });
  }
});

const AUTH_COOKIE_NAME = "shard_auth";
const ADMIN_COOKIE_NAME = "shard_admin_discord";
const DISCORD_STATE_COOKIE = "discord_oauth_state";
const COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const OAUTH_STATE_MAX_AGE_MS = 10 * 60 * 1000;

/**
 * Strip CRLF/whitespace — Windows .env often leaves \r on values.
 * Optional wrapping quotes so values can contain `#` (otherwise dotenv treats `#` as comment).
 */
function trimOAuthEnv(value) {
  let s = String(value || "")
    .replace(/\r/g, "")
    .trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1);
  }
  return s.trim();
}

const DISCORD_CLIENT_ID = trimOAuthEnv(process.env.DISCORD_CLIENT_ID);
const DISCORD_CLIENT_SECRET = trimOAuthEnv(process.env.DISCORD_CLIENT_SECRET);
const GITHUB_CLIENT_ID = trimOAuthEnv(process.env.GITHUB_CLIENT_ID);
const GITHUB_CLIENT_SECRET = trimOAuthEnv(process.env.GITHUB_CLIENT_SECRET);
const GOOGLE_CLIENT_ID = trimOAuthEnv(process.env.GOOGLE_CLIENT_ID);
const GOOGLE_CLIENT_SECRET = trimOAuthEnv(process.env.GOOGLE_CLIENT_SECRET);

/** Discord matches redirect_uri byte-for-byte with OAuth2 → Redirects (no trailing slash). */
function normalizeDiscordRedirectUri(uri) {
  const s = String(uri || "").trim();
  if (!s) {
    return s;
  }
  return s.replace(/\/+$/, "");
}

const DISCORD_REDIRECT_URI = normalizeDiscordRedirectUri(
  process.env.DISCORD_REDIRECT_URI || `http://localhost:${PORT}/api/auth/discord/callback`
);

const DISCORD_LINK_REDIRECT_URI = normalizeDiscordRedirectUri(
  process.env.DISCORD_LINK_REDIRECT_URI || `http://localhost:${PORT}/api/auth/discord/callback/link`
);
const DISCORD_USER_REDIRECT_URI = normalizeDiscordRedirectUri(
  process.env.DISCORD_USER_REDIRECT_URI || `http://localhost:${PORT}/api/auth/discord/callback/user`
);
const GITHUB_REDIRECT_URI = normalizeDiscordRedirectUri(
  process.env.GITHUB_REDIRECT_URI || `http://localhost:${PORT}/api/auth/github/callback`
);
const GOOGLE_REDIRECT_URI = normalizeDiscordRedirectUri(
  process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/api/auth/google/callback`
);

const DISCORD_LINK_STATE_COOKIE = "discord_link_state";
const DISCORD_LINK_USER_COOKIE = "shard_discord_link_user";
const DISCORD_USER_STATE_COOKIE = "discord_user_oauth_state";
const GITHUB_STATE_COOKIE = "github_oauth_state";
const GOOGLE_STATE_COOKIE = "google_oauth_state";

function getDiscordAdminIds() {
  const raw = process.env.DISCORD_ADMIN_IDS || "";
  return raw
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean);
}

function createToken(user) {
  const userId = user.id || user._id;
  return jwt.sign({ sub: userId, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

function setAuthCookie(res, token) {
  res.cookie(AUTH_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: COOKIE_MAX_AGE_MS,
    path: "/",
  });
}

function authRequired(req, res, next) {
  const token = req.cookies[AUTH_COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ error: "Missing authentication cookie." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

function createAdminToken(discordUser) {
  const discordId = String(discordUser.id);
  const username = String(discordUser.username || "");
  const globalName = discordUser.global_name ? String(discordUser.global_name) : "";
  return jwt.sign(
    { sub: discordId, aud: "admin_discord", discordId, username, globalName },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function setAdminCookie(res, token) {
  res.cookie(ADMIN_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: COOKIE_MAX_AGE_MS,
    path: "/",
  });
}

function discordAdminRequired(req, res, next) {
  const token = req.cookies[ADMIN_COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ error: "Admin session required." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.aud !== "admin_discord" || !payload.discordId) {
      return res.status(401).json({ error: "Invalid admin session." });
    }
    req.admin = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired admin session." });
  }
}

function isDiscordConfigured() {
  return Boolean(DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET);
}

function isGithubConfigured() {
  return Boolean(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET);
}

function isGoogleConfigured() {
  return Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
}

function buildDiscordAuthorizeUrl(state, redirectUri = DISCORD_REDIRECT_URI, scopes = "identify") {
  const scopeValue = Array.isArray(scopes) ? scopes.join(" ") : scopes;
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    state,
  });
  params.set("scope", scopeValue);
  // Discord expects space-separated scopes (%20), not form-style plus signs.
  const query = params.toString().replace(/\+/g, "%20");
  return `https://discord.com/oauth2/authorize?${query}`;
}

function buildGithubAuthorizeUrl(state) {
  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: GITHUB_REDIRECT_URI,
    scope: "read:user user:email",
    state,
  });
  return `https://github.com/login/oauth/authorize?${params.toString()}`;
}

function buildGoogleAuthorizeUrl(state) {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    state,
    prompt: "select_account",
    access_type: "online",
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

function setOAuthStateCookie(res, cookieName, state) {
  res.cookie(cookieName, state, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: OAUTH_STATE_MAX_AGE_MS,
    path: "/",
  });
}

function clearOAuthStateCookie(res, cookieName) {
  res.clearCookie(cookieName, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });
}

function authLog(scope, message, extra = null) {
  const prefix = `[auth:${scope}]`;
  if (extra === null || extra === undefined) {
    console.log(`${prefix} ${message}`);
    return;
  }
  console.log(`${prefix} ${message}`, extra);
}

const DISCORD_TOKEN_URLS = [
  "https://discord.com/api/v10/oauth2/token",
  "https://discord.com/api/oauth2/token",
];

/**
 * Tries Discord's documented token URL(s) and client auth styles. invalid_client usually means
 * wrong Application ID / Client Secret pair or a truncated secret in .env (e.g. unquoted `#`).
 */
async function exchangeDiscordAuthorizationCode(code, redirectUriForToken = DISCORD_REDIRECT_URI) {
  const clientId = String(DISCORD_CLIENT_ID);
  const clientSecret = String(DISCORD_CLIENT_SECRET);
  const redirectUri = redirectUriForToken;

  const formWithSecret = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
  }).toString();

  const formCodeOnly = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
  }).toString();

  const basicRaw = Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64");
  const basicRfc6749 = Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`,
    "utf8"
  ).toString("base64");

  const attempts = [];
  for (const tokenUrl of DISCORD_TOKEN_URLS) {
    attempts.push(
      {
        label: `${tokenUrl} (form body)`,
        url: tokenUrl,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "ShardHostingOAuth/1.0",
        },
        body: formWithSecret,
      },
      {
        label: `${tokenUrl} (Basic raw)`,
        url: tokenUrl,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basicRaw}`,
          "User-Agent": "ShardHostingOAuth/1.0",
        },
        body: formCodeOnly,
      },
      {
        label: `${tokenUrl} (Basic RFC-encoded)`,
        url: tokenUrl,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basicRfc6749}`,
          "User-Agent": "ShardHostingOAuth/1.0",
        },
        body: formCodeOnly,
      }
    );
  }

  let lastPayload = {};
  let lastStatus = 400;

  for (const attempt of attempts) {
    const tokenResponse = await fetch(attempt.url, {
      method: "POST",
      headers: attempt.headers,
      body: attempt.body,
    });

    const tokenPayload = await tokenResponse.json().catch(() => ({}));
    lastPayload = tokenPayload;
    lastStatus = tokenResponse.status;

    if (tokenResponse.ok && tokenPayload.access_token) {
      console.log(`Discord token exchange OK: ${attempt.label}`);
      return { ok: true, payload: tokenPayload };
    }

    if (tokenPayload.error === "invalid_grant") {
      return { ok: false, payload: tokenPayload, status: lastStatus };
    }
  }

  return { ok: false, payload: lastPayload, status: lastStatus };
}

function isStrongPassword(password) {
  return /[A-Z]/.test(password) && /\d/.test(password) && /[^A-Za-z0-9]/.test(password) && password.length >= 8;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeEmail(email) {
  return String(email)
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, "")
    .trim()
    .toLowerCase();
}

const DISCORD_PLACEHOLDER_EMAIL_DOMAIN = "discord.user.shard.local";

function isDiscordPlaceholderEmail(email) {
  return String(email || "").toLowerCase().endsWith(`@${DISCORD_PLACEHOLDER_EMAIL_DOMAIN}`);
}

function emailFromDiscordProfile(discordUser) {
  const raw = discordUser?.email ? normalizeEmail(discordUser.email) : "";
  return raw && isValidEmail(raw) ? raw : null;
}

const AVATAR_DATA_URL_MAX = 400000;
const AVATAR_FETCH_MAX_BYTES = 300000;

function discordDefaultAvatarIndex(discordId) {
  try {
    return Number((BigInt(discordId) >> 22n) % 6n);
  } catch {
    const numeric = Number(String(discordId).replace(/\D/g, "") || 0);
    return numeric % 6;
  }
}

function discordAvatarUrl(discordUser) {
  const discordId = String(discordUser?.id || "").trim();
  if (!discordId) {
    return null;
  }
  const avatarHash = discordUser?.avatar;
  if (avatarHash) {
    const ext = String(avatarHash).startsWith("a_") ? "gif" : "png";
    return `https://cdn.discordapp.com/avatars/${discordId}/${avatarHash}.${ext}?size=128`;
  }
  return `https://cdn.discordapp.com/embed/avatars/${discordDefaultAvatarIndex(discordId)}.png`;
}

function githubAvatarUrl(profile) {
  const raw = typeof profile?.avatar_url === "string" ? profile.avatar_url.trim() : "";
  if (!raw) {
    return null;
  }
  const base = raw.split("?")[0];
  return `${base}?s=128`;
}

function googleAvatarUrl(profile) {
  const raw = typeof profile?.picture === "string" ? profile.picture.trim() : "";
  if (!raw) {
    return null;
  }
  if (/=s\d+-c$/.test(raw)) {
    return raw.replace(/=s\d+-c$/, "=s128-c");
  }
  return raw;
}

async function fetchImageAsDataUrl(imageUrl) {
  if (!imageUrl || typeof imageUrl !== "string") {
    return null;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const response = await fetch(imageUrl, { signal: controller.signal, redirect: "follow" });
    clearTimeout(timeout);
    if (!response.ok) {
      return null;
    }

    const contentType = (response.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    const allowed = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);
    const mime = allowed.has(contentType) ? contentType : "image/png";

    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length === 0 || buffer.length > AVATAR_FETCH_MAX_BYTES) {
      return null;
    }

    const dataUrl = `data:${mime};base64,${buffer.toString("base64")}`;
    return dataUrl.length <= AVATAR_DATA_URL_MAX ? dataUrl : null;
  } catch {
    return null;
  }
}

async function avatarDataUrlFromProvider(provider, profile) {
  let imageUrl = null;
  if (provider === "discord") {
    imageUrl = discordAvatarUrl(profile);
  } else if (provider === "github") {
    imageUrl = githubAvatarUrl(profile);
  } else if (provider === "google") {
    imageUrl = googleAvatarUrl(profile);
  }
  return fetchImageAsDataUrl(imageUrl);
}

function isUniqueConstraintError(err) {
  if (!err) {
    return false;
  }

  if (err.code === "23505") {
    return true;
  }

  if (err.code === 11000 || err.code === "11000") {
    return true;
  }

  return err.errorType === "uniqueViolated" || /unique|E11000 duplicate key/i.test(String(err.message || ""));
}

function normalizeAccountUsername(raw) {
  return String(raw || "")
    .trim()
    .toLowerCase();
}

function normalizeIp(ip) {
  if (ip == null) {
    return null;
  }
  const value = String(ip).trim();
  if (!value) {
    return null;
  }
  if (value.startsWith("::ffff:")) {
    return value.slice(7);
  }
  if (value === "::1") {
    return "127.0.0.1";
  }
  return value;
}

function getClientIp(req) {
  const cfIp = req.headers["cf-connecting-ip"];
  if (typeof cfIp === "string" && cfIp.trim()) {
    return normalizeIp(cfIp);
  }

  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.trim()) {
    return normalizeIp(realIp);
  }

  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return normalizeIp(forwarded.split(",")[0]);
  }
  if (Array.isArray(forwarded) && forwarded[0]) {
    return normalizeIp(String(forwarded[0]));
  }

  return normalizeIp(req.ip || req.socket?.remoteAddress || null);
}

async function touchUserLogin(user, ip) {
  if (!user?._id) {
    return user;
  }
  const now = new Date();
  await db.users.update(
    { _id: user._id },
    {
      $set: {
        last_login_ip: ip || user.last_login_ip || null,
        last_login_at: now,
        updated_at: now,
      },
    }
  );
  return db.users.findOne({ _id: user._id });
}

function buildNewUserRecord({
  email,
  username,
  publicUsername,
  passwordHash,
  ip = null,
  discordId = null,
  discordUsername = null,
  avatarDataUrl = null,
}) {
  const now = new Date();
  const record = {
    email,
    username,
    public_username: publicUsername,
    password_hash: passwordHash,
    signup_ip: ip,
    last_login_ip: ip,
    created_at: now,
    updated_at: now,
    last_login_at: now,
  };
  if (discordId) {
    record.discord_id = String(discordId);
  }
  if (discordUsername) {
    record.discord_username = String(discordUsername);
  }
  if (avatarDataUrl) {
    record.avatar_data_url = avatarDataUrl;
  }
  return record;
}

function normalizeSocialUsername(raw, fallback = "user") {
  const base = String(raw || fallback)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
  const seed = base || fallback;
  if (seed.length >= 6) {
    return seed.slice(0, 32);
  }
  return (seed + "000000").slice(0, 6);
}

async function nextAvailablePublicUsername(base) {
  let candidate = base.slice(0, 32);
  let suffix = 1;
  while (true) {
    const existing = await db.users.findOne({ public_username: candidate });
    if (!existing) {
      return candidate;
    }
    const suffixText = String(suffix++);
    const trimTo = Math.max(1, 32 - suffixText.length);
    candidate = `${base.slice(0, trimTo)}${suffixText}`;
  }
}

async function ensureSocialUser({
  email,
  preferredUsername,
  discordId = null,
  discordUsername = null,
  avatarDataUrl = null,
  ip = null,
}) {
  const normalizedEmail = normalizeEmail(email);
  if (!isValidEmail(normalizedEmail)) {
    throw new Error("Social provider did not provide a valid email.");
  }

  let user = null;
  if (discordId) {
    user = await db.users.findOne({ discord_id: String(discordId) });
  }
  if (!user) {
    user = await db.users.findOne({ email: normalizedEmail });
  }

  if (user) {
    const updates = {};
    if (discordId && user.discord_id !== String(discordId)) {
      updates.discord_id = String(discordId);
    }
    if (discordUsername && user.discord_username !== String(discordUsername)) {
      updates.discord_username = String(discordUsername);
    }
    if (
      !isDiscordPlaceholderEmail(normalizedEmail) &&
      isDiscordPlaceholderEmail(user.email)
    ) {
      const conflict = await db.users.findOne({ email: normalizedEmail });
      if (!conflict || String(conflict._id) === String(user._id)) {
        updates.email = normalizedEmail;
      }
    }
    if (avatarDataUrl) {
      updates.avatar_data_url = avatarDataUrl;
    }
    if (Object.keys(updates).length > 0) {
      await db.users.update({ _id: user._id }, { $set: updates });
      user = await db.users.findOne({ _id: user._id });
    }
    return touchUserLogin(user, ip);
  }

  const usernameBase = normalizeSocialUsername(preferredUsername, "user");
  const publicUsername = await nextAvailablePublicUsername(usernameBase);
  const randomPassword = crypto.randomBytes(48).toString("hex");
  const passwordHash = await bcrypt.hash(randomPassword, 12);

  const createdUser = await db.users.insert(
    buildNewUserRecord({
      email: normalizedEmail,
      username: publicUsername,
      publicUsername,
      passwordHash,
      ip,
      discordId,
      discordUsername,
      avatarDataUrl,
    })
  );
  return createdUser;
}

/** 6–32 chars, letters and digits only (after lowercasing). */
function isValidAccountUsername(s) {
  return typeof s === "string" && /^[a-z0-9]{6,32}$/.test(s);
}

app.post("/api/register", async (req, res) => {
  try {
    const { email, password, username } = req.body;

    if (typeof email !== "string" || typeof password !== "string" || typeof username !== "string") {
      return res.status(400).json({ error: "Email, password, and username are required." });
    }

    const normalizedEmail = normalizeEmail(email);
    const normalizedUsername = normalizeAccountUsername(username);

    if (!isValidEmail(normalizedEmail) || normalizedEmail.length > 320) {
      return res.status(400).json({ error: "A valid email is required." });
    }

    if (!isValidAccountUsername(normalizedUsername)) {
      return res.status(400).json({
        error: "Username must be 6–32 characters, letters and numbers only (no spaces or symbols).",
      });
    }

    if (password.length > 128) {
      return res.status(400).json({ error: "Password must be 128 characters or fewer." });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        error: "Password must include 8+ characters, one capital letter, one number, and one symbol.",
      });
    }

    const existingEmail = await db.users.findOne({ email: normalizedEmail });
    if (existingEmail) {
      return res.status(409).json({ error: "Email is already registered." });
    }

    const existingUsername = await db.users.findOne({ public_username: normalizedUsername });
    if (existingUsername) {
      return res.status(409).json({ error: "That username is already taken." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const ip = getClientIp(req);
    const createdUser = await db.users.insert(
      buildNewUserRecord({
        email: normalizedEmail,
        username: normalizedUsername,
        publicUsername: normalizedUsername,
        passwordHash,
        ip,
      })
    );

    const token = createToken(createdUser);
    setAuthCookie(res, token);
    return res.status(201).json({ user: serializeUser(createdUser) });
  } catch (err) {
    if (isUniqueConstraintError(err)) {
      console.error("Register unique constraint error:", err.message || err);
      return res.status(409).json({ error: "Email or username is already registered." });
    }
    console.error("Register error:", err);
    return res.status(500).json({ error: "Unable to create account right now. Please try again." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const normalizedEmail = normalizeEmail(email);
    if (!isValidEmail(normalizedEmail) || normalizedEmail.length > 320) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }

    const user = await db.users.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const ip = getClientIp(req);
    const activeUser = await touchUserLogin(user, ip);
    const token = createToken(activeUser);
    setAuthCookie(res, token);
    return res.json({ user: serializeUser(activeUser) });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Could not log in. Please try again." });
  }
});

function serializeUser(user) {
  return {
    id: user._id,
    email: user.email,
    public_username: user.public_username || null,
    avatar_data_url: user.avatar_data_url || null,
    discord_id: user.discord_id || null,
    discord_username: user.discord_username || null,
  };
}

app.get("/api/me", authRequired, async (req, res) => {
  try {
    const user = await db.users.findOne({ _id: req.user.sub });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    return res.json({ user: serializeUser(user) });
  } catch (err) {
    console.error("Session fetch error:", err);
    return res.status(500).json({ error: "Unable to verify your session. Please log in again." });
  }
});

app.get("/api/session/status", async (req, res) => {
  const userToken = req.cookies[AUTH_COOKIE_NAME];
  const adminToken = req.cookies[ADMIN_COOKIE_NAME];
  let userAuthenticated = false;
  let adminAuthenticated = false;

  if (userToken) {
    try {
      const payload = jwt.verify(userToken, JWT_SECRET);
      const user = await db.users.findOne({ _id: payload.sub });
      userAuthenticated = Boolean(user);
    } catch {
      userAuthenticated = false;
    }
  }

  if (adminToken) {
    try {
      const payload = jwt.verify(adminToken, JWT_SECRET);
      adminAuthenticated = payload?.aud === "admin_discord" && Boolean(payload?.discordId);
    } catch {
      adminAuthenticated = false;
    }
  }

  return res.json({ userAuthenticated, adminAuthenticated });
});

function normalizePublicUsername(raw) {
  if (raw === undefined || raw === null) {
    return null;
  }
  const s = String(raw).trim().toLowerCase();
  return s === "" ? null : s;
}

app.patch("/api/profile", authRequired, async (req, res) => {
  try {
    const { public_username, avatar_data_url } = req.body;
    const user = await db.users.findOne({ _id: req.user.sub });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const set = {};
    const unset = {};

    if (public_username !== undefined) {
      const normalized = normalizePublicUsername(public_username);
      if (normalized === null || normalized === "") {
        return res.status(400).json({ error: "Username is required." });
      }
      if (!isValidAccountUsername(normalized)) {
        return res.status(400).json({
          error: "Username must be 6–32 characters, letters and numbers only (no spaces or symbols).",
        });
      }
      const taken = await db.users.findOne({
        public_username: normalized,
        _id: { $ne: user._id },
      });
      if (taken) {
        return res.status(409).json({ error: "That username is already taken." });
      }
      set.public_username = normalized;
    }

    if (avatar_data_url !== undefined) {
      if (avatar_data_url === null || avatar_data_url === "") {
        unset.avatar_data_url = true;
      } else if (typeof avatar_data_url !== "string") {
        return res.status(400).json({ error: "Invalid avatar data." });
      } else if (!/^data:image\/(png|jpeg|gif|webp);base64,/.test(avatar_data_url)) {
        return res.status(400).json({ error: "Avatar must be a PNG, JPEG, GIF, or WebP image." });
      } else if (avatar_data_url.length > AVATAR_DATA_URL_MAX) {
        return res.status(400).json({ error: "Image is too large. Use a smaller file (under about 300 KB)." });
      } else {
        set.avatar_data_url = avatar_data_url;
      }
    }

    if (Object.keys(set).length === 0 && Object.keys(unset).length === 0) {
      return res.json({ user: serializeUser(user) });
    }

    const updateDoc = {};
    if (Object.keys(set).length) {
      updateDoc.$set = set;
    }
    if (Object.keys(unset).length) {
      updateDoc.$unset = unset;
    }
    await db.users.update({ _id: user._id }, updateDoc);
    const updated = await db.users.findOne({ _id: user._id });
    return res.json({ user: serializeUser(updated) });
  } catch (err) {
    if (isUniqueConstraintError(err)) {
      return res.status(409).json({ error: "That username is already taken." });
    }
    console.error("Profile update error:", err);
    return res.status(500).json({ error: "Could not update profile." });
  }
});

app.patch("/api/profile/email", authRequired, async (req, res) => {
  try {
    const { currentPassword, newEmail } = req.body;
    if (typeof currentPassword !== "string" || typeof newEmail !== "string") {
      return res.status(400).json({ error: "Current password and new email are required." });
    }

    const user = await db.users.findOne({ _id: req.user.sub });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const ok = await bcrypt.compare(currentPassword, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Current password is incorrect." });
    }

    const normalizedEmail = normalizeEmail(newEmail);
    if (!isValidEmail(normalizedEmail) || normalizedEmail.length > 320) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }

    const existing = await db.users.findOne({ email: normalizedEmail });
    if (existing && String(existing._id) !== String(user._id)) {
      return res.status(409).json({ error: "That email is already registered." });
    }

    await db.users.update(
      { _id: user._id },
      {
        $set: {
          email: normalizedEmail,
          username: normalizedEmail,
        },
      }
    );

    const updated = await db.users.findOne({ _id: user._id });
    const token = createToken(updated);
    setAuthCookie(res, token);
    return res.json({ user: serializeUser(updated) });
  } catch (err) {
    if (isUniqueConstraintError(err)) {
      return res.status(409).json({ error: "That email is already registered." });
    }
    console.error("Email change error:", err);
    return res.status(500).json({ error: "Could not update email." });
  }
});

app.patch("/api/profile/password", authRequired, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (typeof currentPassword !== "string" || typeof newPassword !== "string") {
      return res.status(400).json({ error: "Current and new passwords are required." });
    }

    if (newPassword.length > 128) {
      return res.status(400).json({ error: "New password must be 128 characters or fewer." });
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({
        error:
          "New password must include 8+ characters, one capital letter, one number, and one symbol.",
      });
    }

    const user = await db.users.findOne({ _id: req.user.sub });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const ok = await bcrypt.compare(currentPassword, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Current password is incorrect." });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await db.users.update({ _id: user._id }, { $set: { password_hash: passwordHash } });
    return res.json({ message: "Password updated." });
  } catch (err) {
    console.error("Password change error:", err);
    return res.status(500).json({ error: "Could not update password." });
  }
});

app.delete("/api/account", authRequired, async (req, res) => {
  try {
    const { password } = req.body;
    if (typeof password !== "string" || !password) {
      return res.status(400).json({ error: "Password is required to delete your account." });
    }

    const user = await db.users.findOne({ _id: req.user.sub });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Password is incorrect." });
    }

    const removed = await db.users.remove({ _id: user._id }, {});
    if (!removed) {
      return res.status(500).json({ error: "Could not delete account." });
    }

    res.clearCookie(AUTH_COOKIE_NAME, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
    });
    return res.json({ message: "Account deleted." });
  } catch (err) {
    console.error("Account delete error:", err);
    return res.status(500).json({ error: "Could not delete account." });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie(AUTH_COOKIE_NAME, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });
  return res.json({ message: "Logged out." });
});

app.get("/api/auth/providers", (req, res) => {
  return res.json({
    providers: {
      discord: isDiscordConfigured(),
      github: isGithubConfigured(),
      google: isGoogleConfigured(),
    },
  });
});

app.get("/api/auth/discord/user", (req, res) => {
  authLog("discord-user", "OAuth start route hit");
  if (!isDiscordConfigured()) {
    authLog("discord-user", "Discord OAuth is not configured");
    const message =
      "Discord sign-in is not configured on the server. Set DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET.";
    return res.redirect(302, `/login.html?error=${encodeURIComponent(message)}`);
  }

  const state = crypto.randomBytes(24).toString("hex");
  const authorizeUrl = buildDiscordAuthorizeUrl(state, DISCORD_USER_REDIRECT_URI, ["identify", "email"]);
  const parsedAuthorize = new URL(authorizeUrl);
  const redirectUriSent = parsedAuthorize.searchParams.get("redirect_uri");
  authLog("discord-user", "Generated OAuth state and authorize URL", {
    state,
    redirectUri: DISCORD_USER_REDIRECT_URI,
    redirectUriSent,
    authorizeUrl,
  });
  setOAuthStateCookie(res, DISCORD_USER_STATE_COOKIE, state);
  authLog("discord-user", "Set state cookie and redirecting to Discord");
  return res.redirect(302, authorizeUrl);
});

app.get("/api/auth/discord/callback/user", async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;
  const redirectWithError = (message) =>
    res.redirect(302, `/login.html?error=${encodeURIComponent(message)}`);
  authLog("discord-user", "Callback route hit", {
    hasCode: Boolean(code),
    state,
    error,
    errorDescription,
  });

  if (error) {
    authLog("discord-user", "Callback includes Discord error", {
      error,
      errorDescription,
    });
    return redirectWithError(String(errorDescription || error || "Discord authorization failed."));
  }

  if (!isDiscordConfigured()) {
    authLog("discord-user", "Discord OAuth became unconfigured before callback");
    return redirectWithError("Discord OAuth is not configured on the server.");
  }

  const storedState = req.cookies[DISCORD_USER_STATE_COOKIE];
  authLog("discord-user", "Read state cookie on callback", {
    storedState,
  });
  clearOAuthStateCookie(res, DISCORD_USER_STATE_COOKIE);
  authLog("discord-user", "Cleared state cookie");

  if (!code || typeof code !== "string" || !state || typeof state !== "string") {
    authLog("discord-user", "Missing code or state on callback", {
      codeType: typeof code,
      stateType: typeof state,
    });
    return redirectWithError("Missing authorization code or state.");
  }
  if (!storedState || storedState !== state) {
    authLog("discord-user", "State mismatch", {
      storedState,
      callbackState: state,
    });
    return redirectWithError("Invalid OAuth state. Please try signing in again.");
  }

  try {
    authLog("discord-user", "State valid, exchanging authorization code");
    const exchange = await exchangeDiscordAuthorizationCode(code, DISCORD_USER_REDIRECT_URI);
    const tokenPayload = exchange.payload;
    if (!exchange.ok || !tokenPayload.access_token) {
      authLog("discord-user", "Token exchange failed", {
        exchangeOk: exchange.ok,
        tokenPayload,
      });
      const detail = tokenPayload.error_description || tokenPayload.error || "token exchange failed";
      return redirectWithError(`Discord sign-in failed: ${detail}`);
    }
    authLog("discord-user", "Token exchange succeeded");

    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenPayload.access_token}` },
    });
    const discordUser = await userResponse.json().catch(() => ({}));
    authLog("discord-user", "Fetched Discord profile", {
      status: userResponse.status,
      ok: userResponse.ok,
      discordId: discordUser?.id || null,
      username: discordUser?.username || null,
      hasEmail: Boolean(discordUser?.email),
    });
    if (!userResponse.ok) {
      return redirectWithError("Could not read your Discord profile.");
    }

    const discordId = String(discordUser.id || "").trim();
    const discordUsername = String(discordUser.username || "").trim();
    if (!discordId) {
      return redirectWithError("Discord did not provide a valid account id.");
    }

    const discordEmail = emailFromDiscordProfile(discordUser);
    if (!discordEmail) {
      return redirectWithError(
        "Discord did not share your email. Allow email access when authorizing, or sign up with email and password."
      );
    }

    const avatarDataUrl = await avatarDataUrlFromProvider("discord", discordUser);
    const user = await ensureSocialUser({
      email: discordEmail,
      preferredUsername: discordUsername || `discord${discordId.slice(-6)}`,
      discordId,
      discordUsername,
      avatarDataUrl,
      ip: getClientIp(req),
    });
    authLog("discord-user", "Ensured local user for Discord account", {
      userId: user?._id || user?.id || null,
      email: user?.email || null,
    });
    const token = createToken(user);
    setAuthCookie(res, token);
    authLog("discord-user", "Set auth cookie and redirecting to dashboard");
    return res.redirect(302, "/dashboard.html");
  } catch (err) {
    console.error("Discord user OAuth callback error:", err);
    return redirectWithError("Unexpected error during Discord sign-in.");
  }
});

app.get("/api/auth/github", (req, res) => {
  if (!isGithubConfigured()) {
    return res.redirect(
      302,
      `/login.html?error=${encodeURIComponent(
        "GitHub sign-in is not configured on the server. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET."
      )}`
    );
  }
  const state = crypto.randomBytes(24).toString("hex");
  setOAuthStateCookie(res, GITHUB_STATE_COOKIE, state);
  return res.redirect(302, buildGithubAuthorizeUrl(state));
});

app.get("/api/auth/github/callback", async (req, res) => {
  const { code, state, error } = req.query;
  const redirectWithError = (message) =>
    res.redirect(302, `/login.html?error=${encodeURIComponent(message)}`);

  if (error) {
    return redirectWithError("GitHub authorization was cancelled.");
  }
  if (!isGithubConfigured()) {
    return redirectWithError("GitHub OAuth is not configured on the server.");
  }

  const storedState = req.cookies[GITHUB_STATE_COOKIE];
  clearOAuthStateCookie(res, GITHUB_STATE_COOKIE);
  if (!code || typeof code !== "string" || !state || typeof state !== "string") {
    return redirectWithError("Missing authorization code or state.");
  }
  if (!storedState || storedState !== state) {
    return redirectWithError("Invalid OAuth state. Please try signing in again.");
  }

  try {
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: GITHUB_REDIRECT_URI,
      }).toString(),
    });
    const tokenPayload = await tokenResponse.json().catch(() => ({}));
    const accessToken = tokenPayload.access_token;
    if (!tokenResponse.ok || !accessToken) {
      return redirectWithError("GitHub sign-in failed during token exchange.");
    }

    const headers = {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "ShardHostingOAuth/1.0",
    };

    const profileResponse = await fetch("https://api.github.com/user", { headers });
    const profile = await profileResponse.json().catch(() => ({}));
    if (!profileResponse.ok) {
      return redirectWithError("Could not read your GitHub profile.");
    }

    let email = typeof profile.email === "string" ? profile.email.trim().toLowerCase() : "";
    if (!email) {
      const emailsResponse = await fetch("https://api.github.com/user/emails", { headers });
      const emails = await emailsResponse.json().catch(() => []);
      if (emailsResponse.ok && Array.isArray(emails)) {
        const primaryVerified = emails.find((item) => item && item.primary && item.verified);
        const anyVerified = emails.find((item) => item && item.verified);
        const selected = primaryVerified || anyVerified;
        if (selected && typeof selected.email === "string") {
          email = selected.email.trim().toLowerCase();
        }
      }
    }
    if (!isValidEmail(email)) {
      return redirectWithError("GitHub account does not expose a verified email address.");
    }

    const preferredUsername =
      typeof profile.login === "string" && profile.login.trim() ? profile.login.trim() : "githubuser";
    const avatarDataUrl = await avatarDataUrlFromProvider("github", profile);
    const user = await ensureSocialUser({
      email,
      preferredUsername,
      avatarDataUrl,
      ip: getClientIp(req),
    });
    const token = createToken(user);
    setAuthCookie(res, token);
    return res.redirect(302, "/dashboard.html");
  } catch (err) {
    console.error("GitHub OAuth callback error:", err);
    return redirectWithError("Unexpected error during GitHub sign-in.");
  }
});

app.get("/api/auth/google", (req, res) => {
  if (!isGoogleConfigured()) {
    return res.redirect(
      302,
      `/login.html?error=${encodeURIComponent(
        "Google sign-in is not configured on the server. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."
      )}`
    );
  }
  const state = crypto.randomBytes(24).toString("hex");
  setOAuthStateCookie(res, GOOGLE_STATE_COOKIE, state);
  return res.redirect(302, buildGoogleAuthorizeUrl(state));
});

app.get("/api/auth/google/callback", async (req, res) => {
  const { code, state, error } = req.query;
  const redirectWithError = (message) =>
    res.redirect(302, `/login.html?error=${encodeURIComponent(message)}`);

  if (error) {
    return redirectWithError("Google authorization was cancelled.");
  }
  if (!isGoogleConfigured()) {
    return redirectWithError("Google OAuth is not configured on the server.");
  }

  const storedState = req.cookies[GOOGLE_STATE_COOKIE];
  clearOAuthStateCookie(res, GOOGLE_STATE_COOKIE);
  if (!code || typeof code !== "string" || !state || typeof state !== "string") {
    return redirectWithError("Missing authorization code or state.");
  }
  if (!storedState || storedState !== state) {
    return redirectWithError("Invalid OAuth state. Please try signing in again.");
  }

  try {
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code",
      }).toString(),
    });
    const tokenPayload = await tokenResponse.json().catch(() => ({}));
    const accessToken = tokenPayload.access_token;
    if (!tokenResponse.ok || !accessToken) {
      return redirectWithError("Google sign-in failed during token exchange.");
    }

    const profileResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const profile = await profileResponse.json().catch(() => ({}));
    if (!profileResponse.ok) {
      return redirectWithError("Could not read your Google profile.");
    }

    const email = typeof profile.email === "string" ? profile.email.trim().toLowerCase() : "";
    if (!isValidEmail(email)) {
      return redirectWithError("Google account did not provide a valid email.");
    }

    const preferredUsername =
      (typeof profile.name === "string" && profile.name.trim()) ||
      (typeof profile.given_name === "string" && profile.given_name.trim()) ||
      "googleuser";
    const avatarDataUrl = await avatarDataUrlFromProvider("google", profile);
    const user = await ensureSocialUser({
      email,
      preferredUsername,
      avatarDataUrl,
      ip: getClientIp(req),
    });
    const token = createToken(user);
    setAuthCookie(res, token);
    return res.redirect(302, "/dashboard.html");
  } catch (err) {
    console.error("Google OAuth callback error:", err);
    return redirectWithError("Unexpected error during Google sign-in.");
  }
});

app.get("/api/auth/discord", (req, res) => {
  if (!isDiscordConfigured()) {
    const message =
      "Discord OAuth is not configured on the server. Set DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET.";
    return res.redirect(302, `/login.html?error=${encodeURIComponent(message)}`);
  }

  const state = crypto.randomBytes(24).toString("hex");
  res.cookie(DISCORD_STATE_COOKIE, state, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: OAUTH_STATE_MAX_AGE_MS,
    path: "/",
  });

  return res.redirect(302, buildDiscordAuthorizeUrl(state));
});

app.get("/api/auth/discord/callback", async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;
  const redirectWithError = (message) =>
    res.redirect(302, `/login.html?error=${encodeURIComponent(message)}`);

  if (error) {
    return redirectWithError(String(errorDescription || error || "Discord authorization failed."));
  }

  if (!isDiscordConfigured()) {
    return redirectWithError("Discord OAuth is not configured on the server.");
  }

  const storedState = req.cookies[DISCORD_STATE_COOKIE];
  res.clearCookie(DISCORD_STATE_COOKIE, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });

  if (!code || typeof code !== "string" || !state || typeof state !== "string") {
    return redirectWithError("Missing authorization code or state.");
  }

  if (!storedState || storedState !== state) {
    return redirectWithError("Invalid OAuth state. Please try signing in again.");
  }

  const adminIds = getDiscordAdminIds();
  if (adminIds.length === 0) {
    console.warn("DISCORD_ADMIN_IDS is empty — no Discord accounts can access the admin area.");
    return redirectWithError("Admin access is not configured.");
  }

  try {
    const exchange = await exchangeDiscordAuthorizationCode(code, DISCORD_REDIRECT_URI);
    const tokenPayload = exchange.payload;

    if (!exchange.ok) {
      console.error("Discord token exchange failed:", tokenPayload);
      const discordErr = tokenPayload.error;
      const discordDesc =
        typeof tokenPayload.error_description === "string"
          ? tokenPayload.error_description
          : "";
      if (discordErr === "invalid_client") {
        return redirectWithError(
          "Discord rejected Client ID or Client Secret (invalid_client). Confirm in Developer Portal → OAuth2: Application ID matches DISCORD_CLIENT_ID exactly; reset Client Secret, paste the new secret into .env. If the secret contains # or spaces, wrap it in double quotes in .env. Restart the server after saving."
        );
      }
      if (discordErr === "invalid_grant") {
        return redirectWithError(
          "Discord authorization code expired or already used. Close the tab and sign in again from the admin page."
        );
      }
      const detail = discordDesc || discordErr || "token exchange failed";
      return redirectWithError(`Discord sign-in failed: ${detail}`);
    }

    const accessToken = tokenPayload.access_token;
    if (!accessToken) {
      return redirectWithError("Discord did not return an access token.");
    }

    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const discordUser = await userResponse.json().catch(() => ({}));
    if (!userResponse.ok) {
      console.error("Discord user fetch failed:", discordUser);
      return redirectWithError("Could not read your Discord profile.");
    }

    const discordId = String(discordUser.id || "");
    if (!adminIds.includes(discordId)) {
      return redirectWithError("Your Discord account is not authorized for admin access.");
    }

    const adminToken = createAdminToken(discordUser);
    setAdminCookie(res, adminToken);
    return res.redirect(302, "/admin_dashboard.html");
  } catch (err) {
    console.error("Discord OAuth callback error:", err);
    return redirectWithError("Unexpected error during Discord sign-in.");
  }
});

app.get("/api/auth/discord/link", authRequired, async (req, res) => {
  try {
    if (!isDiscordConfigured()) {
      return res.redirect(
        302,
        `/profile.html?error=${encodeURIComponent("Discord OAuth is not configured on the server.")}`
      );
    }

    const user = await db.users.findOne({ _id: req.user.sub });
    if (!user) {
      return res.redirect(302, "/login.html");
    }
    if (user.discord_id) {
      return res.redirect(302, "/profile.html?discord=already");
    }

    const state = crypto.randomBytes(24).toString("hex");
    const linkToken = jwt.sign({ sub: req.user.sub, aud: "discord_link" }, JWT_SECRET, {
      expiresIn: "10m",
    });

    res.cookie(DISCORD_LINK_STATE_COOKIE, state, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: OAUTH_STATE_MAX_AGE_MS,
      path: "/",
    });
    res.cookie(DISCORD_LINK_USER_COOKIE, linkToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: OAUTH_STATE_MAX_AGE_MS,
      path: "/",
    });

    return res.redirect(302, buildDiscordAuthorizeUrl(state, DISCORD_LINK_REDIRECT_URI, ["identify", "email"]));
  } catch (err) {
    console.error("Discord link start error:", err);
    return res.redirect(
      302,
      `/profile.html?error=${encodeURIComponent("Could not start Discord linking.")}`
    );
  }
});

app.get("/api/auth/discord/callback/link", async (req, res) => {
  const redirectErr = (message) =>
    res.redirect(302, `/profile.html?error=${encodeURIComponent(message)}`);

  const { code, state, error, error_description: errorDescription } = req.query;

  if (error) {
    return redirectErr(String(errorDescription || error || "Discord authorization failed."));
  }

  if (!isDiscordConfigured()) {
    return redirectErr("Discord OAuth is not configured on the server.");
  }

  const storedState = req.cookies[DISCORD_LINK_STATE_COOKIE];
  const linkCookie = req.cookies[DISCORD_LINK_USER_COOKIE];
  res.clearCookie(DISCORD_LINK_STATE_COOKIE, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });
  res.clearCookie(DISCORD_LINK_USER_COOKIE, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });

  if (!code || typeof code !== "string" || !state || typeof state !== "string") {
    return redirectErr("Missing authorization code or state.");
  }

  if (!storedState || storedState !== state) {
    return redirectErr("Invalid OAuth state. Try linking again from your profile.");
  }

  let userId;
  try {
    const payload = jwt.verify(linkCookie, JWT_SECRET);
    if (payload.aud !== "discord_link" || !payload.sub) {
      return redirectErr("Invalid link session. Try again from your profile.");
    }
    userId = payload.sub;
  } catch {
    return redirectErr("Link session expired. Try again from your profile.");
  }

  try {
    const exchange = await exchangeDiscordAuthorizationCode(code, DISCORD_LINK_REDIRECT_URI);
    const tokenPayload = exchange.payload;

    if (!exchange.ok) {
      console.error("Discord link token exchange failed:", tokenPayload);
      const discordErr = tokenPayload.error;
      const discordDesc =
        typeof tokenPayload.error_description === "string" ? tokenPayload.error_description : "";
      if (discordErr === "invalid_grant") {
        return redirectErr("Authorization expired. Try linking again from your profile.");
      }
      const detail = discordDesc || discordErr || "token exchange failed";
      return redirectErr(`Discord sign-in failed: ${detail}`);
    }

    const accessToken = tokenPayload.access_token;
    if (!accessToken) {
      return redirectErr("Discord did not return an access token.");
    }

    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const discordUser = await userResponse.json().catch(() => ({}));
    if (!userResponse.ok) {
      console.error("Discord user fetch failed:", discordUser);
      return redirectErr("Could not read your Discord profile.");
    }

    const discordId = String(discordUser.id || "");
    const discordUsername = String(discordUser.username || "");

    const taken = await db.users.findOne({ discord_id: discordId, _id: { $ne: userId } });
    if (taken) {
      return redirectErr("This Discord account is already linked to another user.");
    }

    const linkUpdates = { discord_id: discordId, discord_username: discordUsername };
    const discordEmail = emailFromDiscordProfile(discordUser);
    const avatarDataUrl = await avatarDataUrlFromProvider("discord", discordUser);
    if (avatarDataUrl) {
      linkUpdates.avatar_data_url = avatarDataUrl;
    }
    const existingUser = await db.users.findOne({ _id: userId });
    if (
      discordEmail &&
      existingUser &&
      isDiscordPlaceholderEmail(existingUser.email)
    ) {
      const conflict = await db.users.findOne({ email: discordEmail });
      if (!conflict || String(conflict._id) === String(userId)) {
        linkUpdates.email = discordEmail;
      }
    }

    await db.users.update({ _id: userId }, { $set: linkUpdates });

    return res.redirect(302, "/profile.html?discord=linked");
  } catch (err) {
    console.error("Discord link callback error:", err);
    return redirectErr("Unexpected error while linking Discord.");
  }
});

app.get("/api/admin/me", discordAdminRequired, (req, res) => {
  const { discordId, username, globalName } = req.admin;
  return res.json({
    admin: {
      discordId,
      username,
      globalName: globalName || null,
    },
  });
});

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie(ADMIN_COOKIE_NAME, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });
  return res.json({ message: "Admin session ended." });
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
