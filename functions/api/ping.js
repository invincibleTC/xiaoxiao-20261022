/* 临时诊断接口（用完可删）
 * GET /api/ping
 * 只报告「环境变量里有哪些名字、KV 绑定是不是真对象」，不返回任何值，不泄露密钥。
 */
export async function onRequestGet(context) {
  const env = context.env || {};
  const names = Object.keys(env).sort();

  /* 只露出跟存储/鉴权相关的名字，其余一律不返回 */
  const watch = names.filter((k) => /KV|SITE|ADMIN|AUTH|MAIL|BUCKET|COS/i.test(k));

  const kv = env.SITE_KV || env.GARMENTS_KV || null;

  return new Response(JSON.stringify({
    ok: true,
    runtime: "edgeone-functions",
    /* 这些名字存在 = 已经注入；不存在 = 没注入 */
    envKeys: watch,
    kv: {
      pickedFrom: env.SITE_KV ? "SITE_KV" : (env.GARMENTS_KV ? "GARMENTS_KV" : "none"),
      type: typeof kv,
      isKvObject: !!(kv && typeof kv === "object" && typeof kv.get === "function"),
      /* 常见误配：被同名环境变量覆盖成字符串 */
      looksLikeString: typeof kv === "string"
    },
    /* 真能读 KV 就顺带测一下读写 */
    probe: kv && typeof kv.get === "function"
      ? await probeKV(kv)
      : { skipped: "函数没有拿到 KV 对象，无法读写" }
  }, null, 2), {
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}

async function probeKV(kv) {
  try {
    const stamp = "probe-" + Date.now();
    await kv.put("__ping", stamp, { expirationTtl: 120 });
    const back = await kv.get("__ping");
    const siteConfig = await kv.get("site-config");
    return {
      writeOk: back === stamp,
      readOk: !!back,
      hasSiteConfig: !!siteConfig,
      siteConfigSize: siteConfig ? String(siteConfig).length : 0
    };
  } catch (e) {
    return { error: String((e && e.message) || e) };
  }
}
