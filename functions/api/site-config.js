/* 站点配置接口
 * GET  /api/site-config  公开读取（访客也要看到最新门店 / 联系 / 页脚 / 形象片等）
 * PUT  /api/site-config  管理员写入：必须带有效签名 token（HMAC 验签，伪造无效）
 *
 * KV 绑定：优先用 SITE_KV；没绑就退回已存在的 GARMENTS_KV。
 * 存的是一个 JSON：{ films, spaces, series, stores, contacts, footer, categories, … }
 */
export async function onRequestGet(context) {
  const kv = getKV(context.env);
  if (!kv) return json({ config: null, note: "未绑定 KV（SITE_KV 或 GARMENTS_KV）" });
  const raw = await kv.get("site-config");
  if (!raw) return json({ config: null });
  let config = null;
  try { config = JSON.parse(raw); }
  catch (e) { return json({ config: null, note: "配置解析失败" }); }
  return json({ config });
}

export async function onRequestPut(context) {
  const { request, env } = context;

  if (!env.AUTH_SECRET) {
    return json({ error: "服务端未配置 AUTH_SECRET，已拒绝写入" }, 503);
  }
  /* 验签：token 必须是 /api/auth 用 AUTH_SECRET 签发的、未过期的管理员 token，
     且版本号要跟当前密码一致（改过密码后旧 token 立即失效） */
  const payload = await verifyToken(env.AUTH_SECRET, bearer(request), await currentVer(env));
  if (!payload) return unauthorized();

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: "请求格式错误" }, 400); }
  if (!body || !body.config || typeof body.config !== "object") {
    return json({ error: "缺少 config" }, 400);
  }

  const kv = getKV(env);
  if (!kv) return json({ error: "未绑定 KV（SITE_KV 或 GARMENTS_KV）" }, 500);

  const payloadStr = JSON.stringify(body.config);
  if (payloadStr.length > 8 * 1024 * 1024) {
    return json({ error: "配置过大（超过 8MB），请压缩图片后再保存" }, 413);
  }

  await kv.put("site-config", payloadStr);
  return json({ config: body.config });
}

/* ── 鉴权工具（各函数文件内联一份）────────────────────────────── */

function bearer(request) {
  const h = request.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

async function verifyToken(secret, token, ver) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const expect = await hmacHex(secret, parts[1]);
  if (!safeEqual(expect, String(parts[2]).toLowerCase())) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(parts[1])); }
  catch (e) { return null; }
  if (!payload || payload.role !== "admin") return null;
  if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return null;
  if (ver && payload.ver !== undefined && Number(payload.ver) !== Number(ver)) return null;
  return payload;
}

/* 当前密码版本号：改过密码后旧 token 一律作废 */
async function currentVer(env) {
  const kv = resolveKV(env);
  if (!kv) return 1;
  const raw = await kv.get("admin-cred");
  if (!raw) return 1;
  try { return Number(JSON.parse(raw).ver) || 1; } catch (e) { return 1; }
}

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function unauthorized() {
  return json({ error: "未登录或登录已过期，请重新登录" }, 401);
}

/* KV 绑定兼容三种注入方式（env / 全局绑定名 / globalThis） */
function resolveKV(env) {
  const e = env || {};
  let kv = e.SITE_KV || e.GARMENTS_KV || null;
  if (!kv) { try { if (typeof GARMENTS_KV !== "undefined") kv = GARMENTS_KV; } catch (err) { } }
  if (!kv) { try { if (typeof SITE_KV !== "undefined") kv = SITE_KV; } catch (err) { } }
  if (!kv && typeof globalThis !== "undefined") kv = globalThis.GARMENTS_KV || globalThis.SITE_KV || null;
  return (kv && typeof kv.get === "function") ? kv : null;
}

function getKV(env) { return resolveKV(env); }

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}
