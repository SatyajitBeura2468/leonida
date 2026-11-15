import crypto from "node:crypto";
import { get, put, del } from "@vercel/blob";

const SESSION_PATH = "beuraverse/twitch/session.json";
const STATE_PREFIX = "beuraverse/twitch/pending/";

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function encryptionKey() {
  const value = requiredEnv("TWITCH_TOKEN_ENCRYPTION_KEY");
  if (!/^[a-f0-9]{64}$/i.test(value)) {
    throw new Error("TWITCH_TOKEN_ENCRYPTION_KEY must be a 32-byte hex value.");
  }
  return Buffer.from(value, "hex");
}

function encryptJson(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final()
  ]);
  return JSON.stringify({
    version: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: encrypted.toString("base64")
  });
}

function decryptJson(value) {
  const payload = JSON.parse(value);
  if (payload.version !== 1) throw new Error("Unsupported encrypted session format.");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(payload.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.data, "base64")),
    decipher.final()
  ]);
  return JSON.parse(decrypted.toString("utf8"));
}

async function readPrivateJson(pathname) {
  const blob = await get(pathname, { access: "private" });
  if (!blob || blob.statusCode !== 200) return null;
  const text = await new Response(blob.stream).text();
  return decryptJson(text);
}

async function writePrivateJson(pathname, value) {
  await put(pathname, encryptJson(value), {
    access: "private",
    addRandomSuffix: false,
    allowOverwrite: true,
    contentType: "application/json",
    cacheControlMaxAge: 0
  });
}

export async function saveOAuthState(state) {
  await writePrivateJson(`${STATE_PREFIX}${state}.json`, {
    createdAt: Date.now()
  });
}

export async function consumeOAuthState(state) {
  if (!state || !/^[a-f0-9]{64}$/i.test(state)) return false;
  const pathname = `${STATE_PREFIX}${state}.json`;
  const pending = await readPrivateJson(pathname);
  await del(pathname).catch(() => {});
  return Boolean(pending && Date.now() - pending.createdAt <= 10 * 60 * 1000);
}

export function buildTwitchAuthorizationUrl(state) {
  const url = new URL("https://id.twitch.tv/oauth2/authorize");
  url.search = new URLSearchParams({
    client_id: requiredEnv("TWITCH_CLIENT_ID"),
    redirect_uri: requiredEnv("TWITCH_REDIRECT_URI"),
    response_type: "code",
    scope: ""
  }).toString();
  url.searchParams.set("state", state);
  return url.toString();
}

async function exchangeAuthorizationCode(code) {
  const body = new URLSearchParams({
    client_id: requiredEnv("TWITCH_CLIENT_ID"),
    client_secret: requiredEnv("TWITCH_CLIENT_SECRET"),
    code,
    grant_type: "authorization_code",
    redirect_uri: requiredEnv("TWITCH_REDIRECT_URI")
  });
  const response = await fetch("https://id.twitch.tv/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.message || "Twitch token exchange failed.");
  return result;
}

async function validateAccessToken(accessToken) {
  const response = await fetch("https://id.twitch.tv/oauth2/validate", {
    headers: { Authorization: `OAuth ${accessToken}` }
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.message || "Twitch access token validation failed.");
  if (result.client_id !== requiredEnv("TWITCH_CLIENT_ID") || !result.user_id) {
    throw new Error("The Twitch token does not belong to this BeuraVerse application.");
  }
  return result;
}

async function fetchUser(accessToken) {
  const response = await fetch("https://api.twitch.tv/helix/users", {
    headers: {
      "Client-Id": requiredEnv("TWITCH_CLIENT_ID"),
      Authorization: `Bearer ${accessToken}`
    }
  });
  const result = await response.json();
  if (!response.ok || !result.data?.[0]) {
    throw new Error(result.message || "Unable to retrieve the authorized Twitch profile.");
  }
  const user = result.data[0];
  return {
    id: user.id,
    login: user.login,
    displayName: user.display_name,
    description: user.description,
    profileImageUrl: user.profile_image_url,
    viewCount: user.view_count,
    createdAt: user.created_at
  };
}

async function persistSession(token, validation, profile) {
  const session = {
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    expiresAt: Date.now() + Number(token.expires_in || 14400) * 1000,
    scopes: token.scope || validation.scopes || [],
    userId: validation.user_id,
    profile,
    validatedAt: Date.now(),
    connectedAt: Date.now()
  };
  await writePrivateJson(SESSION_PATH, session);
  return session;
}

export async function completeTwitchOAuth(code) {
  const token = await exchangeAuthorizationCode(code);
  const validation = await validateAccessToken(token.access_token);
  const profile = await fetchUser(token.access_token);
  return persistSession(token, validation, profile);
}

async function refreshSession(session) {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: session.refreshToken,
    client_id: requiredEnv("TWITCH_CLIENT_ID"),
    client_secret: requiredEnv("TWITCH_CLIENT_SECRET")
  });
  const response = await fetch("https://id.twitch.tv/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const token = await response.json();
  if (!response.ok) {
    await del(SESSION_PATH).catch(() => {});
    throw new Error("Your Twitch authorization expired or was revoked. Run start_twitch_authorization again.");
  }
  const validation = await validateAccessToken(token.access_token);
  const profile = await fetchUser(token.access_token);
  const next = {
    ...session,
    accessToken: token.access_token,
    refreshToken: token.refresh_token || session.refreshToken,
    expiresAt: Date.now() + Number(token.expires_in || 14400) * 1000,
    scopes: token.scope || validation.scopes || session.scopes,
    userId: validation.user_id,
    profile,
    validatedAt: Date.now()
  };
  await writePrivateJson(SESSION_PATH, next);
  return next;
}

export async function getConnectedTwitchSession() {
  const session = await readPrivateJson(SESSION_PATH);
  if (!session) {
    throw new Error("Twitch is not connected yet. Call start_twitch_authorization and approve BeuraVerse first.");
  }
  if (Date.now() - Number(session.validatedAt || 0) > 55 * 60 * 1000) {
    try {
      await validateAccessToken(session.accessToken);
      session.validatedAt = Date.now();
      await writePrivateJson(SESSION_PATH, session);
    } catch {
      return refreshSession(session);
    }
  }
  return session;
}

export async function twitchGet(path, initialSession) {
  let session = initialSession || await getConnectedTwitchSession();
  const makeRequest = () => fetch(`https://api.twitch.tv/helix/${path}`, {
    headers: {
      "Client-Id": requiredEnv("TWITCH_CLIENT_ID"),
      Authorization: `Bearer ${session.accessToken}`
    }
  });
  let response = await makeRequest();
  if (response.status === 401) {
    session = await refreshSession(session);
    response = await makeRequest();
  }
  const result = await response.json();
  if (!response.ok) throw new Error(result.message || "Twitch API request failed.");
  return { data: result.data || [], session };
}

export async function getChannelOverview() {
  let session = await getConnectedTwitchSession();
  const userResult = await twitchGet(`users?id=${encodeURIComponent(session.userId)}`, session);
  session = userResult.session;
  const channelResult = await twitchGet(`channels?broadcaster_id=${encodeURIComponent(session.userId)}`, session);
  session = channelResult.session;
  const streamsResult = await twitchGet(`streams?user_id=${encodeURIComponent(session.userId)}`, session);
  return {
    profile: userResult.data[0] || session.profile,
    channel: channelResult.data[0] || null,
    live: streamsResult.data[0] || null,
    connectedScopes: session.scopes || [],
    connectedAt: session.connectedAt
  };
}

export async function getLiveStatus() {
  const session = await getConnectedTwitchSession();
  const result = await twitchGet(`streams?user_id=${encodeURIComponent(session.userId)}`, session);
  return {
    channel: session.profile?.displayName || session.profile?.login,
    isLive: result.data.length > 0,
    stream: result.data[0] || null
  };
}

export async function getRecentVideos() {
  const session = await getConnectedTwitchSession();
  const result = await twitchGet(
    `videos?user_id=${encodeURIComponent(session.userId)}&first=5&sort=time`,
    session
  );
  return result.data;
}

export async function getRecentClips() {
  const session = await getConnectedTwitchSession();
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const params = new URLSearchParams({
    broadcaster_id: session.userId,
    first: "5",
    started_at: weekAgo.toISOString(),
    ended_at: now.toISOString()
  });
  const result = await twitchGet(`clips?${params.toString()}`, session);
  return result.data;
}

export async function disconnectTwitch() {
  const session = await readPrivateJson(SESSION_PATH);
  if (!session) return false;
  const body = new URLSearchParams({
    client_id: requiredEnv("TWITCH_CLIENT_ID"),
    token: session.accessToken
  });
  await fetch("https://id.twitch.tv/oauth2/revoke", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  }).catch(() => {});
  await del(SESSION_PATH).catch(() => {});
  return true;
}
