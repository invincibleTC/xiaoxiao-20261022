/* 管理员认证接口
 * POST /api/auth           登录 → { token, username, role, exp }
 * PUT  /api/auth           改密码：需有效 token + 旧密码正确（新凭据写进 KV）
 * GET  /api/auth           已登录时返回预留邮箱的脱敏形式（不返回完整邮箱）
 *
 * 凭据来源优先级：KV「admin-cred」> 环境变量。
 *   环境变量在边缘函数里是只读的，所以改密码必须写 KV；
 *   没绑 KV 时只能靠环境变量（此时改密码不可用）。
 *
 * 环境变量：
 *   ADMIN_USERNAME        管理员用户名
 *   ADMIN_PASSWORD_HASH   sha256(ADMIN_SALT + ":" + 密码)（tools/gen-admin-hash.html 生成）
 *   ADMIN_SALT            随机盐
 *   AUTH_SECRET           token 签名密钥
 *   ADMIN_EMAIL           管理员邮箱（仅服务端可见，用于重置密码）
 *   MAIL_PROVIDER / MAIL_API_KEY / MAIL_FROM   改密码成功后发一封告知邮件（不配则跳过）
 */
const TOKEN_TTL = 12 * 60 * 60;
const FAIL_LIMIT = 10;
const CRED_KEY = "admin-cred";

export async function onRequestPost(context) {
  const { request, env } = context;

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: "请求格式错误" }, 400); }

  const username = (body.username || "").trim();
  const password = (body.password || "").trim();
  if (!username || !password) return json({ error: "账号和密码不能为空" }, 400);

  const cred = await getCred(env);
  if (!cred) return json({ error: "服务端未配置管理员凭据，请联系站点维护者" }, 503);

  const ip = clientIP(request);
  if (await tooMany(env, "authfail:" + ip, FAIL_LIMIT, 15 * 60)) {
    return json({ error: "尝试次数过多，请 15 分钟后再试" }, 429);
  }

  const okUser = safeEqual(String(username).toLowerCase(), String(cred.username).toLowerCase());
  const hash = await sha256Hex(cred.salt + ":" + password);
  const okPass = safeEqual(hash, String(cred.hash).toLowerCase());

  if (!okUser || !okPass) {
    await bump(env, "authfail:" + ip, 15 * 60);
    return json({ error: "账号或密码不正确" }, 401);
  }

  await clear(env, "authfail:" + ip);
  const now = Math.floor(Date.now() / 1000);
  const exp = now + TOKEN_TTL;
  if (!env.AUTH_SECRET) return json({ error: "服务端未配置 AUTH_SECRET" }, 503);
  const token = await signToken(env.AUTH_SECRET, {
    sub: cred.username, role: "admin", ver: cred.ver || 1, iat: now, exp: exp
  });
  return json({ token, username: cred.username, role: "admin", exp });
}

/* 改密码：必须知道旧密码，且持有有效 token；新哈希写进 KV */
export async function onRequestPut(context) {
  const { request, env } = context;
  if (!env.AUTH_SECRET) return json({ error: "服务端未配置 AUTH_SECRET" }, 503);

  const cred = await getCred(env);
  if (!cred) return json({ error: "服务端未配置管理员凭据" }, 503);

  const payload = await verifyToken(env.AUTH_SECRET, bearer(request), cred.ver || 1);
  if (!payload) return unauthorized();

  const kv = credKV(env);
  if (!kv) return json({ error: "未绑定 KV，无法修改密码（请在控制台绑定 GARMENTS_KV）" }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: "请求格式错误" }, 400); }

  const oldPass = (body.oldPassword || "").trim();
  const newPass = (body.newPassword || "").trim();
  if (!oldPass || !newPass) return json({ error: "旧密码和新密码都要填" }, 400);
  if (newPass.length < 8) return json({ error: "新密码至少 8 位" }, 400);
  if (newPass === oldPass) return json({ error: "新密码不能和旧密码一样" }, 400);

  const oldHash = await sha256Hex(cred.salt + ":" + oldPass);
  if (!safeEqual(oldHash, String(cred.hash).toLowerCase())) {
    return json({ error: "旧密码不正确" }, 401);
  }

  const salt = randHex(16);
  const hash = await sha256Hex(salt + ":" + newPass);
  const ver = (Number(cred.ver) || 1) + 1;           /* 版本号 +1 → 其它设备的旧 token 全部失效 */
  await kv.put(CRED_KEY, JSON.stringify({ username: cred.username, salt, hash, ver: ver, at: Date.now() }));
  await clear(env, "authfail:" + clientIP(request));

  /* 改完给预留邮箱发一封告知邮件：不是本人操作时能立刻发现 */
  if (env.ADMIN_EMAIL) {
    await sendMail(env, env.ADMIN_EMAIL, "管理员密码已修改",
      "<p>你的画册后台管理员密码刚刚被修改。</p>" +
      "<p>如果不是你本人操作，请立刻用「忘记密码」重新设置，并更换 AUTH_SECRET。</p>" +
      "<p style='color:#8C8378;font-size:12px'>时间：" + new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }) + "</p>");
  }

  const now = Math.floor(Date.now() / 1000);
  const token = await signToken(env.AUTH_SECRET, {
    sub: cred.username, role: "admin", ver: ver, iat: now, exp: now + TOKEN_TTL
  });
  return json({ ok: true, token, exp: now + TOKEN_TTL });
}

/* 账户信息：只给登录者看邮箱的脱敏形式，完整邮箱不出服务端 */
export async function onRequestGet(context) {
  const { request, env } = context;
  if (!env.AUTH_SECRET) return json({ error: "服务端未配置 AUTH_SECRET" }, 503);
  const cred = await getCred(env);
  if (!cred) return json({ error: "服务端未配置管理员凭据" }, 503);
  const payload = await verifyToken(env.AUTH_SECRET, bearer(request), cred.ver || 1);
  if (!payload) return unauthorized();
  return json({
    username: (cred && cred.username) || "",
    hasEmail: !!env.ADMIN_EMAIL,
    emailMask: env.ADMIN_EMAIL ? maskEmail(env.ADMIN_EMAIL) : "",
    credSource: await credFrom(env)
  });
}

/* ── 凭据读取：KV 优先，环境变量兜底 ─────────────────────────── */

/* KV 绑定兼容三种注入方式：
 *   1) env.GARMENTS_KV —— Cloudflare Pages / EdgeOne Functions 的 env 参数
 *   2) 直接引用绑定名 —— EdgeOne Makers 文档示例的写法（绑定注入到全局作用域）
 *   3) globalThis.GARMENTS_KV
 * 任一方式拿到带 get() 的对象即视为已绑定。
 */
function resolveKV(env) {
  const e = env || {};
  let kv = e.SITE_KV || e.GARMENTS_KV || null;
  if (!kv) { try { if (typeof GARMENTS_KV !== "undefined") kv = GARMENTS_KV; } catch (err) { } }
  if (!kv) { try { if (typeof SITE_KV !== "undefined") kv = SITE_KV; } catch (err) { } }
  if (!kv && typeof globalThis !== "undefined") kv = globalThis.GARMENTS_KV || globalThis.SITE_KV || null;
  return (kv && typeof kv.get === "function") ? kv : null;
}

function credKV(env) { return resolveKV(env); }

async function getCred(env) {
  const kv = credKV(env);
  if (kv) {
    const raw = await kv.get(CRED_KEY);
    if (raw) {
      try {
        const c = JSON.parse(raw);
        if (c && c.username && c.salt && c.hash) {
          c.ver = Number(c.ver) || 1;          /* 密码版本号：改一次 +1，旧 token 立即失效 */
          return c;
        }
      } catch (e) { /* 数据坏了就退回环境变量 */ }
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
async function credFrom(env) {
  const kv = credKV(env);
  if (kv) { const raw = await kv.get(CRED_KEY); if (raw) return "kv"; }
  return "env";
}
function maskEmail(mail) {
  var at = mail.indexOf("@");
  if (at < 1) return "***";
  var name = mail.slice(0, at), dom = mail.slice(at + 1);
  var head = name.slice(0, Math.min(3, name.length));
  return head + "****" + "@" + dom;
}

/* ── 邮件发送（改密码告知；重置邮件见 reset.js）────────────── */

async function sendMail(env, to, subject, html) {
  const provider = (env.MAIL_PROVIDER || "").toLowerCase();
  try {
    if (provider === "resend") {
      const r = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + env.MAIL_API_KEY },
        body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject: subject, html: html })
      });
      return r.ok || (await r.text(), false);
    }
    if (provider === "tencent") {
      return await tencentSES(env, to, subject, html);
    }
  } catch (e) { /* 邮件失败不影响主流程 */ }
  return false;
}

/* 腾讯云 SES（TC3-HMAC-SHA256 签名，纯 fetch 实现，不引 SDK） */
async function tencentSES(env, to, subject, html) {
  const host = "ses.tencentcloudapi.com";
  const action = "SendEmail";
  const version = "2020-10-02";
  const payload = JSON.stringify({
    FromEmailAddress: env.MAIL_FROM,
    Destination: [to],
    Subject: subject,
    Simple: { Html: html, Text: html.replace(/<[^>]+>/g, "") }
  });
  const ts = Math.floor(Date.now() / 1000);
  const date = new Date(ts * 1000).toISOString().slice(0, 10);

  const canonical =
    "POST\n/\n\n" +
    "content-type:application/json\n" +
    "host:" + host + "\n" +
    "x-tc-action:" + action.toLowerCase() + "\n\n" +
    "content-type;host;x-tc-action\n" +
    await sha256Hex(payload);

  const s2s = "TC3-HMAC-SHA256\n" + ts + "\n" + date + "/ses/tc3_request\n" + await sha256Hex(canonical);

  const kDate = await hmacRaw(("TC3" + env.MAIL_SECRET_KEY), date);
  const kService = await hmacRaw(kDate, "ses");
  const kSigning = await hmacRaw(kService, "tc3_request");
  const sig = await hmacHexRaw(kSigning, s2s);

  const auth = "TC3-HMAC-SHA256 Credential=" + env.MAIL_SECRET_ID + "/" + date +
    "/ses/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature=" + sig;

  const r = await fetch("https://" + host + "/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Host": host,
      "X-TC-Action": action,
      "X-TC-Version": version,
      "X-TC-Timestamp": String(ts),
      "Authorization": auth
    },
    body: payload
  });
  return r.ok;
}

/* ── 通用工具（各函数文件内联一份）────────────────────────── */

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
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  const hex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
  return "v1." + body + "." + hex;
}

async function verifyToken(secret, token, ver) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const expect = await hmacHexRaw(secret, parts[1]);
  if (!safeEqual(expect, String(parts[2]).toLowerCase())) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(parts[1])); } catch (e) { return null; }
  if (!payload || payload.role !== "admin") return null;
  if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return null;
  /* 密码改过之后签发的版本号更高，旧 token 一律作废 */
  if (ver && payload.ver !== undefined && Number(payload.ver) !== Number(ver)) return null;
  return payload;
}

async function hmacRaw(keyBytes, msg) {
  const key = await crypto.subtle.importKey("raw",
    typeof keyBytes === "string" ? new TextEncoder().encode(keyBytes) : keyBytes,
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
}
async function hmacHexRaw(keyOrBytes, msg) {
  const sig = await hmacRaw(keyOrBytes, msg);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function bearer(request) {
  const h = request.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
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

function unauthorized() {
  return json({ error: "未登录或登录已过期，请重新登录" }, 401);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}
