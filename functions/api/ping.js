/* 临时诊断接口（用完可删）
 * GET /api/ping
 * 只报告「绑定/环境变量是否存在、注入方式是哪一种」，不返回任何值，不泄露密钥。
 */
export async function onRequestGet(context) {
  const env = context.env || {};
  const names = Object.keys(env).sort();

  /* 只露出跟存储/鉴权相关的名字，其余一律不返回 */
  const watch = names.filter((k) => /KV|SITE|ADMIN|AUTH|MAIL|BUCKET|COS/i.test(k));

  /* 逐个检测 KV 可能出现的三个位置 */
  const probe = {
    "env.GARMENTS_KV": safeType(() => env.GARMENTS_KV),
    "env.SITE_KV": safeType(() => env.SITE_KV),
    "global GARMENTS_KV": safeType(() => (typeof GARMENTS_KV === "undefined" ? undefined : GARMENTS_KV)),
    "global SITE_KV": safeType(() => (typeof SITE_KV === "undefined" ? undefined : SITE_KV)),
    "globalThis.GARMENTS_KV": safeType(() => globalThis.GARMENTS_KV),
    "globalThis.SITE_KV": safeType(() => globalThis.SITE_KV)
  };

  /* 找出真正可用的那个 */
  const found = pickKV(env);

  return new Response(JSON.stringify({
    ok: true,
    runtime: "edgeone-functions",
    envKeys: watch,
    injection: probe,
    picked: found.from,
    isKvObject: !!(found.kv && typeof found.kv.get === "function"),
    /* 真拿到就实测读写 */
    test: found.kv && typeof found.kv.get === "function"
      ? await testKV(found.kv)
      : { skipped: "任何位置都没拿到 KV 对象" }
  }, null, 2), {
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}

function safeType(fn) {
  try {
    const v = fn();
    if (v === undefined) return "undefined";
    if (v === null) return "null";
    if (typeof v === "object") return typeof v.get === "function" ? "kv-object" : "object(no get)";
    return typeof v;
  } catch (e) {
    return "throw: " + ((e && e.message) || e);
  }
}

function pickKV(env) {
  const e = env || {};
  let kv = e.SITE_KV || e.GARMENTS_KV || null, from = e.SITE_KV ? "env.SITE_KV" : (e.GARMENTS_KV ? "env.GARMENTS_KV" : "");
  if (!kv) { try { if (typeof GARMENTS_KV !== "undefined" && GARMENTS_KV) { kv = GARMENTS_KV; from = "GARMENTS_KV"; } } catch (err) { } }
  if (!kv) { try { if (typeof SITE_KV !== "undefined" && SITE_KV) { kv = SITE_KV; from = "SITE_KV"; } } catch (err) { } }
  if (!kv) {
    const g = globalThis;
    kv = (g && (g.GARMENTS_KV || g.SITE_KV)) || null;
    if (kv) from = "globalThis";
  }
  if (!(kv && typeof kv.get === "function")) return { kv: null, from: "none" };
  return { kv: kv, from: from || "unknown" };
}

async function testKV(kv) {
  try {
    const stamp = "probe-" + Date.now();
    await kv.put("__ping", stamp, { expirationTtl: 120 });
    const back = await kv.get("__ping");
    const siteConfig = await kv.get("site-config");
    const cred = await kv.get("admin-cred");
    return {
      writeOk: back === stamp,
      readOk: !!back,
      hasSiteConfig: !!siteConfig,
      siteConfigSize: siteConfig ? String(siteConfig).length : 0,
      hasAdminCred: !!cred
    };
  } catch (e) {
    return { error: String((e && e.message) || e) };
  }
}
