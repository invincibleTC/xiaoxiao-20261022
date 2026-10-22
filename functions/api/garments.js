/* 商品列表接口
 * GET  /api/garments           公开读取
 * POST /api/garments           管理员新增：必须带有效签名 token
 *
 * KV 绑定：GARMENTS_KV（EdgeOne Pages 控制台 → 项目设置 → KV 命名空间）
 */
export async function onRequestGet(context) {
  const { env } = context;
  if (!env.GARMENTS_KV) return json({ garments: [], note: "未绑定 GARMENTS_KV" });
  const raw = await env.GARMENTS_KV.get("list");
  const garments = raw ? JSON.parse(raw) : [];
  return json({ garments });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.AUTH_SECRET) {
    return json({ error: "服务端未配置 AUTH_SECRET，已拒绝写入" }, 503);
  }
  const payload = await verifyToken(env.AUTH_SECRET, bearer(request), await currentVer(env));
  if (!payload) return unauthorized();

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: "请求格式错误" }, 400); }
  if (!body || !body.name) return json({ error: "缺少服装名称" }, 400);
  if (!env.GARMENTS_KV) return json({ error: "未绑定 GARMENTS_KV" }, 500);

  const raw = await env.GARMENTS_KV.get("list");
  const list = raw ? JSON.parse(raw) : [];
  const item = {
    id: body.id || ("g_" + Date.now().toString(36)),
    name: body.name,
    code: body.code || "",
    category: body.category || "",
    series: body.series || "",
    sid: body.sid || "",
    price: body.price || "",
    desc: body.desc || "",
    detail: body.detail || "",
    media: body.media || "",
    type: body.type || "image",
    owner: payload.sub || "admin"
  };
  list.unshift(item);
  await env.GARMENTS_KV.put("list", JSON.stringify(list));
  return json({ item });
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
  const kv = env.SITE_KV || env.GARMENTS_KV || null;
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
