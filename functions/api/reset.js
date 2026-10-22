/* 忘记密码：发重置链接到「服务端环境变量里的管理员邮箱」
 * POST /api/reset  { username }                 发起：账号对了才发信，但对外始终同一句提示
 * PUT  /api/reset  { token, password }          完成重置：验签 + 一次性 + 写新凭据
 *
 * 安全要点：
 *   - 邮箱只存在环境变量 ADMIN_EMAIL，接口永不返回完整邮箱，前端也就无从展示
 *   - 重置链接 30 分钟有效，且用后即焚（KV 记录 jti）
 *   - 同一 IP 15 分钟最多发起 5 次
 *
 * 环境变量：
 *   ADMIN_EMAIL      管理员邮箱（收重置邮件）
 *   MAIL_PROVIDER    resend | tencent
 *   MAIL_API_KEY     Resend 的 API Key
 *   MAIL_SECRET_ID / MAIL_SECRET_KEY / MAIL_FROM   腾讯云 SES
 */
const RESET_TTL = 30 * 60;
const SEND_LIMIT = 5;

export async function onRequestPost(context) {
  const { request, env } = context;

  const done = json({ ok: true, note: "如果该账号存在，重置邮件已发送到预留邮箱" });

  if (!env.AUTH_SECRET || !env.ADMIN_EMAIL) {
    /* 没配邮箱就不泄露任何信息，仍返回同一句提示 */
    return done;
  }
  const kv = credKV(env);
  if (!kv) return done;

  let body;
  try { body = await request.json(); }
  catch (e) { return done; }

  const cred = await getCred(env);
  if (!cred) return done;

  const username = (body.username || "").trim();
  if (!safeEqual(String(username).toLowerCase(), String(cred.username).toLowerCase())) return done;

  const ip = clientIP(request);
  if (await tooMany(env, "resetsend:" + ip, SEND_LIMIT, 15 * 60)) return done;

  const now = Math.floor(Date.now() / 1000);
  const jti = randHex(12);
  const token = await signToken(env.AUTH_SECRET, {
    sub: cred.username, role: "reset", jti: jti, iat: now, exp: now + RESET_TTL
  });

  const page = pageUrl(request);
  const link = page + (page.indexOf("?") === -1 ? "?" : "&") + "reset=" + encodeURIComponent(token);

  const html =
    '<div style="font:14px/1.9 -apple-system,\'PingFang SC\',\'Microsoft YaHei\',sans-serif;color:#2B2825">' +
    '<p>有人在潇潇时尚画册后台申请重置管理员密码。</p>' +
    '<p><a href="' + link + '" style="display:inline-block;padding:12px 24px;background:#2B2825;color:#F6F4F0;' +
    'text-decoration:none;letter-spacing:.1em;font-size:13px">重置密码</a></p>' +
    '<p style="color:#8C8378;font-size:12px">链接 30 分钟内有效，用后即失效。' +
    '如果不是你本人申请，忽略这封邮件即可，密码不会改变。</p>' +
    '<p style="color:#8C8378;font-size:12px">打不开按钮就复制这个链接：<br>' + link + '</p></div>';

  await sendMail(env, env.ADMIN_EMAIL, "重置画册后台管理员密码", html);
  await bump(env, "resetsend:" + ip, 15 * 60);
  return done;
}

export async function onRequestPut(context) {
  const { request, env } = context;
  if (!env.AUTH_SECRET) return json({ error: "服务端未配置 AUTH_SECRET" }, 503);

  const kv = credKV(env);
  if (!kv) return json({ error: "未绑定 KV，无法重置密码（请在控制台绑定 GARMENTS_KV）" }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: "请求格式错误" }, 400); }

  const token = (body.token || "").trim();
  const newPass = (body.password || "").trim();
  if (!token || !newPass) return json({ error: "参数不完整" }, 400);
  if (newPass.length < 8) return json({ error: "新密码至少 8 位" }, 400);

  const payload = await verifyToken(env.AUTH_SECRET, token);
  if (!payload || payload.role !== "reset" || !payload.jti) {
    return json({ error: "重置链接无效或已过期，请重新申请" }, 401);
  }
  /* 用后即焚 */
  if (await kv.get("resetused:" + payload.jti)) {
    return json({ error: "这个重置链接已经用过了，请重新申请" }, 401);
  }

  const cred = await getCred(env);
  if (!cred) return json({ error: "服务端未配置管理员凭据" }, 503);

  const salt = randHex(16);
  const hash = await sha256Hex(salt + ":" + newPass);
  const ver = (Number(cred.ver) || 1) + 1;            /* 重置后旧 token 立即失效 */
  await kv.put("admin-cred", JSON.stringify({ username: cred.username, salt, hash, ver: ver, at: Date.now() }));
  await kv.put("resetused:" + payload.jti, "1", { expirationTtl: 24 * 60 * 60 });
  await clear(env, "authfail:" + clientIP(request));

  /* 重置后直接签发登录 token，省得再输一次 */
  const now = Math.floor(Date.now() / 1000);
  const login = await signToken(env.AUTH_SECRET, {
    sub: cred.username, role: "admin", ver: ver, iat: now, exp: now + 12 * 60 * 60
  });
  return json({ ok: true, token: login, username: cred.username, role: "admin", exp: now + 12 * 60 * 60 });
}

/* ── 邮件发送 ──────────────────────────────────────────────── */

async function sendMail(env, to, subject, html) {
  const provider = (env.MAIL_PROVIDER || "").toLowerCase();
  try {
    if (provider === "resend") {
      const r = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + env.MAIL_API_KEY },
        body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject: subject, html: html })
      });
      if (r.ok) return true;
      await r.text();
      return false;
    }
    if (provider === "tencent") return await tencentSES(env, to, subject, html);
  } catch (e) { /* 发信失败不影响主流程 */ }
  return false;
}

/* 腾讯云 SES：TC3-HMAC-SHA256 签名，纯 fetch 实现，不引 SDK */
async function tencentSES(env, to, subject, html) {
  const host = "ses.tencentcloudapi.com";
  const action = "SendEmail";
  const ts = Math.floor(Date.now() / 1000);
  const date = new Date(ts * 1000).toISOString().slice(0, 10);
  const payload = JSON.stringify({
    FromEmailAddress: env.MAIL_FROM,
    Destination: [to],
    Subject: subject,
    Simple: { Html: html, Text: html.replace(/<[^>]+>/g, "") }
  });

  const canonical =
    "POST\n/\n\n" +
    "content-type:application/json\nhost:" + host + "\n" +
    "x-tc-action:" + action.toLowerCase() + "\n\n" +
    "content-type;host;x-tc-action\n" + await sha256Hex(payload);

  const s2s = "TC3-HMAC-SHA256\n" + ts + "\n" + date + "/ses/tc3_request\n" + await sha256Hex(canonical);

  const kDate = await hmacBytes("TC3" + env.MAIL_SECRET_KEY, date);
  const kService = await hmacBytes(kDate, "ses");
  const kSigning = await hmacBytes(kService, "tc3_request");
  const sig = await hmacHex(kSigning, s2s);

  const r = await fetch("https://" + host + "/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Host": host,
      "X-TC-Action": action,
      "X-TC-Version": "2020-10-02",
      "X-TC-Timestamp": String(ts),
      "Authorization": "TC3-HMAC-SHA256 Credential=" + env.MAIL_SECRET_ID + "/" + date +
        "/ses/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature=" + sig
    },
    body: payload
  });
  return r.ok;
}

/* ── 通用工具（各函数文件内联一份）────────────────────────── */

function credKV(env) { return env.SITE_KV || env.GARMENTS_KV || null; }

async function getCred(env) {
  const kv = credKV(env);
  if (kv) {
    const raw = await kv.get("admin-cred");
    if (raw) {
      try {
        const c = JSON.parse(raw);
        if (c && c.username && c.salt && c.hash) return c;
      } catch (e) { /* 退回环境变量 */ }
    }
  }
  if (env.ADMIN_USERNAME && env.ADMIN_SALT && env.ADMIN_PASSWORD_HASH) {
    return {
      username: env.ADMIN_USERNAME, salt: env.ADMIN_SALT,
      hash: env.ADMIN_PASSWORD_HASH, ver: 1
    };
  }
  return null;
}
/* 当前密码版本号：写接口用它判断 token 是否已被改密码作废 */
async function currentVer(env) {
  const kv = credKV(env);
  if (!kv) return 1;
  const raw = await kv.get("admin-cred");
  if (!raw) return 1;
  try { return Number(JSON.parse(raw).ver) || 1; } catch (e) { return 1; }
}

function pageUrl(request) {
  const u = new URL(request.url);
  return u.origin + u.pathname;
}

function clientIP(request) {
  return request.headers.get("CF-Connecting-IP")
    || (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim()
    || "unknown";
}

function randHex(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return Array.from(a).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function signToken(secret, p) {
  const body = b64urlEncode(JSON.stringify(p));
  const hex = await hmacHex(secret, body);
  return "v1." + body + "." + hex;
}
async function verifyToken(secret, token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const expect = await hmacHex(secret, parts[1]);
  if (!safeEqual(expect, String(parts[2]).toLowerCase())) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(parts[1])); } catch (e) { return null; }
  if (!payload) return null;
  if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return null;
  return payload;
}

async function hmacBytes(keyBytes, msg) {
  const key = await crypto.subtle.importKey("raw",
    typeof keyBytes === "string" ? new TextEncoder().encode(keyBytes) : keyBytes,
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
}
async function hmacHex(keyOrBytes, msg) {
  const sig = await hmacBytes(keyOrBytes, msg);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function tooMany(env, key, limit, ttlSec) {
  const kv = credKV(env);
  if (!kv) return false;
  const raw = await kv.get(key);
  if (!raw) return false;
  let d;
  try { d = JSON.parse(raw); } catch (e) { return false; }
  if (!d || Date.now() - d.since > ttlSec * 1000) return false;
  return d.n >= limit;
}
async function bump(env, key, ttlSec) {
  const kv = credKV(env);
  if (!kv) return;
  const now = Date.now();
  let d = { n: 0, since: now };
  const raw = await kv.get(key);
  if (raw) { try { d = JSON.parse(raw); } catch (e) { d = { n: 0, since: now }; } }
  if (!d || now - d.since > ttlSec * 1000) d = { n: 0, since: now };
  d.n += 1;
  await kv.put(key, JSON.stringify(d), { expirationTtl: ttlSec });
}
async function clear(env, key) {
  const kv = credKV(env);
  if (kv) await kv.delete(key);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}
