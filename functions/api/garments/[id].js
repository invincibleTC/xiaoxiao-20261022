/* 单个商品：编辑与删除
 * PUT    /api/garments/:id    必须带有效签名 token
 * DELETE /api/garments/:id    必须带有效签名 token
 */
export async function onRequestPut(context) {
  const { request, env, params } = context;

  if (!env.AUTH_SECRET) {
    return json({ error: "服务端未配置 AUTH_SECRET，已拒绝写入" }, 503);
  }
  const payload = await verifyToken(env.AUTH_SECRET, bearer(request), await currentVer(env));
  if (!payload) return unauthorized();

  const kv = resolveKV(env);
  if (!kv) return json({ error: "未绑定 KV（GARMENTS_KV）" }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: "请求格式错误" }, 400); }

  const id = params.id;
  const raw = await kv.get("list");
  const list = raw ? JSON.parse(raw) : [];
  let found = null;
  const next = list.map(function (x) {
    if (x.id !== id) return x;
    found = Object.assign({}, x, {
      name: body.name || x.name,
      code: body.code !== undefined ? body.code : x.code,
      category: body.category !== undefined ? body.category : x.category,
      series: body.series !== undefined ? body.series : x.series,
      sid: body.sid !== undefined ? body.sid : x.sid,
      price: body.price !== undefined ? body.price : x.price,
      desc: body.desc !== undefined ? body.desc : x.desc,
      detail: body.detail !== undefined ? body.detail : x.detail,
      media: body.media || x.media,
      type: body.type || x.type
    });
    return found;
  });
  if (!found) return json({ error: "未找到该内容" }, 404);
  await kv.put("list", JSON.stringify(next));
  return json({ item: found });
}

export async function onRequestDelete(context) {
  const { request, env, params } = context;

  if (!env.AUTH_SECRET) {
    return json({ error: "服务端未配置 AUTH_SECRET，已拒绝写入" }, 503);
  }
  const payload = await verifyToken(env.AUTH_SECRET, bearer(request), await currentVer(env));
  if (!payload) return unauthorized();

  const kv = resolveKV(env);
  if (!kv) return json({ error: "未绑定 KV（GARMENTS_KV）" }, 500);

  const id = params.id;
  const raw = await kv.get("list");
  const list = raw ? JSON.parse(raw) : [];
  const next = list.filter(function (x) { return x.id !== id; });
  if (next.length === list.length) return json({ error: "未找到该内容" }, 404);
  await kv.put("list", JSON.stringify(next));
  return json({ ok: true });
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

/* KV 绑定兼容三种注入方式（env / 全局绑定名 / globalThis） */
function resolveKV(env) {
  const e = env || {};
  let kv = e.SITE_KV || e.GARMENTS_KV || null;
  if (!kv) { try { if (typeof GARMENTS_KV !== "undefined") kv = GARMENTS_KV; } catch (err) { } }
  if (!kv) { try { if (typeof SITE_KV !== "undefined") kv = SITE_KV; } catch (err) { } }
  if (!kv && typeof globalThis !== "undefined") kv = globalThis.GARMENTS_KV || globalThis.SITE_KV || null;
  return (kv && typeof kv.get === "function") ? kv : null;
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

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}
