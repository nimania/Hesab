/*
 * ربات و سرور «حساب غذا» — نیما داینز
 * Cloudflare Worker (رایگان)
 *
 * کارها:
 *  ۱) بررسی عضویت کاربر در کانال (برای باز شدن مینی‌اپ)
 *  ۲) گرفتن و ذخیره‌ی شماره‌ی موبایل کاربر
 *  ۳) پشتیبانی: پیام کاربر به ربات → برای نیما فرستاده می‌شه؛ نیما ریپلای می‌کنه → به کاربر می‌رسه
 *  ۴) دستورهای نیما در ربات: /stats (آمار)  و  /export (فایل اکسل کاربران و شماره‌ها)
 *
 * تنظیمات لازم در Cloudflare (Settings → Variables and Secrets):
 *   BOT_TOKEN  (Secret)  توکن ربات از BotFather
 *   SETUP_KEY  (Secret)  یک رمز دلخواه، مثلاً  hesab-1405-xyz
 *   CHANNEL    (Text)    @nimasdiner
 *   APP_URL    (Text)    https://nimania.github.io/Hesab/
 * و یک KV با نام متغیر  USERS  (Settings → Bindings → KV namespace)
 */

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    try {
      if (req.method === "OPTIONS") return cors(new Response(null, { status: 204 }));

      if (url.pathname === "/api/check" && req.method === "POST") {
        return cors(await apiCheck(req, env));
      }

      if (url.pathname === "/webhook" && req.method === "POST") {
        if (req.headers.get("X-Telegram-Bot-Api-Secret-Token") !== (await hookSecret(env))) {
          return new Response("forbidden", { status: 403 });
        }
        const update = await req.json();
        ctx.waitUntil(onUpdate(update, env).catch((e) => console.log("update error", e && e.stack || e)));
        return new Response("ok");
      }

      if (url.pathname === "/setup") return await setup(url, env);

      return text("ربات حساب غذا روشن است ✅");
    } catch (e) {
      console.log("fatal", e && e.stack || e);
      return cors(json({ ok: false, error: "server" }, 500));
    }
  },
};

/* ================= API برای مینی‌اپ ================= */

async function apiCheck(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "bad_request" }, 400); }

  const user = await verifyInitData(body && body.initData, env.BOT_TOKEN);
  if (!user) return json({ ok: false, error: "auth" }, 401);

  const member = await isMember(env, user.id);
  if (member === null) return json({ ok: false, error: "member_check" }, 502);

  const rec = await ensureUser(env, user);
  return json({ ok: true, member, hasPhone: !!rec.phone });
}

/* اعتبارسنجی داده‌ای که تلگرام به مینی‌اپ می‌ده (تا کسی نتونه جعل کنه) */
async function verifyInitData(initData, botToken) {
  if (!initData || typeof initData !== "string" || !botToken) return null;
  const p = new URLSearchParams(initData);
  const hash = p.get("hash");
  if (!hash) return null;
  p.delete("hash");
  const dcs = [...p.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const enc = new TextEncoder();
  const k1 = await crypto.subtle.importKey("raw", enc.encode("WebAppData"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const secret = await crypto.subtle.sign("HMAC", k1, enc.encode(botToken));
  const k2 = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = hex(await crypto.subtle.sign("HMAC", k2, enc.encode(dcs)));
  if (!safeEqual(sig, hash.toLowerCase())) return null;

  const auth = Number(p.get("auth_date") || 0);
  if (!auth || Date.now() / 1000 - auth > 2 * 86400) return null;

  try {
    const u = JSON.parse(p.get("user") || "null");
    return u && u.id ? u : null;
  } catch { return null; }
}

async function isMember(env, userId) {
  const r = await tg(env, "getChatMember", { chat_id: env.CHANNEL, user_id: userId });
  if (!r.ok) { console.log("getChatMember failed", JSON.stringify(r)); return null; }
  const s = r.result.status;
  return s === "creator" || s === "administrator" || s === "member" || (s === "restricted" && !!r.result.is_member);
}

/* ================= ربات تلگرام ================= */

async function onUpdate(u, env) {
  const m = u.message;
  if (!m || !m.from || m.chat.type !== "private") return;

  const txt = m.text || "";
  const admin = await env.USERS.get("admin");

  // نیما یک بار این رو می‌فرسته تا ادمین پشتیبانی بشه:  /admin رمز
  if (/^\/admin(\s|$)/.test(txt)) {
    const key = txt.split(/\s+/)[1];
    if (key && env.SETUP_KEY && key === env.SETUP_KEY) {
      await env.USERS.put("admin", String(m.from.id));
      return send(env, m.chat.id, "✅ حالا تو ادمین پشتیبانی هستی.\n\n" + ADMIN_HELP);
    }
    return send(env, m.chat.id, "❌ رمز درست نیست.");
  }

  if (admin && String(m.from.id) === admin) return onAdmin(m, env);
  if (m.contact) return onContact(m, env, admin);
  if (txt.startsWith("/")) return onStart(m, env);
  return relayToAdmin(m, env, admin);
}

async function onStart(m, env) {
  const rec = await ensureUser(env, m.from);
  const ch = channelName(env);
  const name = m.from.first_name || "";

  await send(env, m.chat.id,
    `سلام ${name}! 👋\n` +
    `اینجا ربات «حساب غذا»ی نیما داینزه: بفهم هر غذای منوت واقعاً چقدر سود می‌ده.\n\n` +
    `برای استفاده:\n` +
    `۱) عضو کانال @${ch} باش\n` +
    (rec.phone ? "" : `۲) شماره‌ات رو با دکمه‌ی «📱 ارسال شماره موبایل» پایین صفحه بفرست\n`) +
    `${rec.phone ? "۲" : "۳"}) ابزار رو با دکمه‌ی «حساب غذا» باز کن\n\n` +
    `💬 هر سؤالی داشتی همین‌جا بنویس؛ مستقیم به دست نیما می‌رسه.`,
    {
      reply_markup: rec.phone
        ? { remove_keyboard: true }
        : { keyboard: [[{ text: "📱 ارسال شماره موبایل", request_contact: true }]], resize_keyboard: true, one_time_keyboard: true },
    });

  await send(env, m.chat.id, "👇", { reply_markup: appKeyboard(env) });
}

async function onContact(m, env, admin) {
  const c = m.contact;
  if (!c.user_id || c.user_id !== m.from.id) {
    return send(env, m.chat.id, "لطفاً شماره‌ی خودت رو با دکمه‌ی «📱 ارسال شماره موبایل» بفرست.");
  }
  const rec = await ensureUser(env, m.from);
  const isNew = !rec.phone;
  rec.phone = normPhone(c.phone_number);
  rec.phone_at = new Date().toISOString();
  await putUser(env, rec);

  await send(env, m.chat.id, "✅ شماره‌ات ثبت شد، ممنون! حالا می‌تونی حساب غذا رو باز کنی.", { reply_markup: { remove_keyboard: true } });
  await send(env, m.chat.id, "👇", { reply_markup: appKeyboard(env) });

  if (isNew && admin) {
    await send(env, admin, `🆕 کاربر جدید\n${who(rec)}\n📱 ${rec.phone}`);
  }
}

async function relayToAdmin(m, env, admin) {
  if (!admin) {
    return send(env, m.chat.id, "پیامت رسید، ولی پشتیبانی هنوز راه‌اندازی نشده. کمی بعد دوباره پیام بده.");
  }
  const rec = await ensureUser(env, m.from);
  const head = await send(env, admin,
    `💬 پیام پشتیبانی\n${who(rec)}\n📱 ${rec.phone || "شماره ثبت نشده"}\n\n↩️ برای جواب دادن، روی همین پیام یا پیام زیرش «ریپلای» کن.`);
  const copy = await tg(env, "copyMessage", { chat_id: admin, from_chat_id: m.chat.id, message_id: m.message_id });

  const ttl = { expirationTtl: 60 * 60 * 24 * 60 }; // ۶۰ روز
  if (head.ok) await env.USERS.put("m:" + head.result.message_id, String(m.from.id), ttl);
  if (copy.ok) await env.USERS.put("m:" + copy.result.message_id, String(m.from.id), ttl);

  await send(env, m.chat.id, "✅ پیامت به نیما رسید. جوابش همین‌جا برات میاد.");
}

const ADMIN_HELP =
  "راهنمای ادمین:\n" +
  "• پیام کاربرها برات فرستاده می‌شه. برای جواب، روی پیامشون «ریپلای» کن (متن، عکس، ویس، فایل… همه کار می‌کنه).\n" +
  "• /stats  آمار کاربرها\n" +
  "• /export  فایل اکسل کاربرها و شماره‌ها";

async function onAdmin(m, env) {
  const txt = (m.text || "").trim();

  if (m.reply_to_message) {
    const uid = await env.USERS.get("m:" + m.reply_to_message.message_id);
    if (!uid) return send(env, m.chat.id, "این پیام به هیچ کاربری وصل نیست. روی پیامِ خودِ کاربر ریپلای کن.");
    const r = await tg(env, "copyMessage", { chat_id: uid, from_chat_id: m.chat.id, message_id: m.message_id });
    return send(env, m.chat.id, r.ok ? "✅ فرستاده شد." : "❌ نرسید (احتمالاً کاربر ربات رو بلاک کرده).",
      { reply_parameters: { message_id: m.message_id } });
  }

  if (txt === "/stats") {
    const users = await listUsers(env);
    const withPhone = users.filter((u) => u.phone).length;
    const day = Date.now() - 86400000, week = Date.now() - 7 * 86400000;
    const newDay = users.filter((u) => Date.parse(u.first_seen) > day).length;
    const newWeek = users.filter((u) => Date.parse(u.first_seen) > week).length;
    return send(env, m.chat.id,
      `📊 آمار حساب غذا\n` +
      `کل کاربرها: ${fa(users.length)}\n` +
      `با شماره‌ی ثبت‌شده: ${fa(withPhone)}\n` +
      `جدید در ۲۴ ساعت: ${fa(newDay)}\n` +
      `جدید در ۷ روز: ${fa(newWeek)}`);
  }

  if (txt === "/export") {
    const users = await listUsers(env);
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const rows = [["id", "first_name", "last_name", "username", "phone", "first_seen", "phone_at"]]
      .concat(users.map((u) => [u.id, u.first_name, u.last_name, u.username ? "@" + u.username : "", u.phone ? "\t" + u.phone : "", u.first_seen, u.phone_at || ""]));
    const csv = "﻿" + rows.map((r) => r.map(q).join(",")).join("\r\n");
    const fd = new FormData();
    fd.append("chat_id", String(m.chat.id));
    fd.append("caption", `${fa(users.length)} کاربر`);
    fd.append("document", new Blob([csv], { type: "text/csv" }), "hesab-users.csv");
    await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendDocument`, { method: "POST", body: fd });
    return;
  }

  await send(env, m.chat.id, ADMIN_HELP, { reply_markup: appKeyboard(env) });
}

/* ================= راه‌اندازی یک‌کلیکی ================= */

async function setup(url, env) {
  if (!env.SETUP_KEY || url.searchParams.get("key") !== env.SETUP_KEY) return text("کلید نادرست است.", 403);
  const missing = ["BOT_TOKEN", "CHANNEL", "APP_URL"].filter((k) => !env[k]);
  if (!env.USERS) missing.push("USERS (KV)");
  if (missing.length) return text("❌ این‌ها هنوز تنظیم نشده‌اند: " + missing.join("، "));

  const out = [];
  const me = await tg(env, "getMe");
  if (!me.ok) return text("❌ توکن ربات درست نیست: " + (me.description || ""));
  out.push(`ربات: @${me.result.username} ✅`);

  const w = await tg(env, "setWebhook", {
    url: url.origin + "/webhook",
    secret_token: await hookSecret(env),
    allowed_updates: ["message"],
  });
  out.push(`اتصال ربات به سرور (webhook): ${w.ok ? "✅" : "❌ " + (w.description || "")}`);

  const mb = await tg(env, "setChatMenuButton", { menu_button: { type: "web_app", text: "حساب غذا", web_app: { url: env.APP_URL } } });
  out.push(`دکمه‌ی منوی ربات: ${mb.ok ? "✅" : "❌ " + (mb.description || "")}`);

  await tg(env, "setMyCommands", { commands: [{ command: "start", description: "شروع و باز کردن حساب غذا" }] });

  const cm = await tg(env, "getChatMember", { chat_id: env.CHANNEL, user_id: me.result.id });
  const isAdmin = cm.ok && cm.result.status === "administrator";
  out.push(`ادمین بودن ربات در کانال ${env.CHANNEL}: ${isAdmin ? "✅" : "❌ ربات رو در کانال ادمین کن و دوباره همین صفحه رو باز کن"}`);

  const admin = await env.USERS.get("admin");
  out.push(`ادمین پشتیبانی: ${admin ? "✅" : "❌ در ربات بفرست:  /admin " + "(همان SETUP_KEY)"}`);

  out.push("", `آدرس سرور برای گذاشتن در index.html:`, url.origin);
  return text(out.join("\n"));
}

/* ================= ذخیره‌ی کاربرها ================= */

async function getUser(env, id) {
  const v = await env.USERS.get("u:" + id);
  return v ? JSON.parse(v) : null;
}
async function putUser(env, rec) {
  // رکورد هم به‌عنوان مقدار و هم metadata ذخیره می‌شه تا خروجی گرفتن سریع باشه
  await env.USERS.put("u:" + rec.id, JSON.stringify(rec), { metadata: rec });
}
async function ensureUser(env, from) {
  let rec = await getUser(env, from.id);
  const fresh = { first_name: from.first_name || "", last_name: from.last_name || "", username: from.username || "" };
  if (!rec) {
    rec = { id: from.id, ...fresh, phone: "", first_seen: new Date().toISOString() };
    await putUser(env, rec);
  } else if (rec.first_name !== fresh.first_name || rec.last_name !== fresh.last_name || rec.username !== fresh.username) {
    Object.assign(rec, fresh);
    await putUser(env, rec);
  }
  return rec;
}
async function listUsers(env) {
  const users = [];
  let cursor;
  do {
    const r = await env.USERS.list({ prefix: "u:", cursor });
    for (const k of r.keys) users.push(k.metadata || (await getUser(env, k.name.slice(2))));
    cursor = r.list_complete ? undefined : r.cursor;
  } while (cursor);
  return users.filter(Boolean).sort((a, b) => String(a.first_seen).localeCompare(String(b.first_seen)));
}

/* ================= ابزار ================= */

function tg(env, method, body) {
  return fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  }).then((r) => r.json()).catch((e) => ({ ok: false, description: String(e) }));
}
function send(env, chatId, textMsg, extra) {
  return tg(env, "sendMessage", { chat_id: chatId, text: textMsg, ...(extra || {}) });
}
function appKeyboard(env) {
  return {
    inline_keyboard: [
      [{ text: "🧮 باز کردن حساب غذا", web_app: { url: env.APP_URL } }],
      [{ text: "📢 کانال نیما داینز", url: "https://t.me/" + channelName(env) }],
    ],
  };
}
function channelName(env) { return String(env.CHANNEL || "").replace(/^@/, ""); }
function who(rec) {
  const name = [rec.first_name, rec.last_name].filter(Boolean).join(" ") || "بی‌نام";
  return `👤 ${name}${rec.username ? " (@" + rec.username + ")" : ""} · 🆔 ${rec.id}`;
}
function normPhone(p) { p = String(p || "").replace(/[^\d+]/g, ""); return p.startsWith("+") ? p : "+" + p; }
function fa(n) { return Number(n).toLocaleString("fa-IR"); }
function hex(buf) { return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join(""); }
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function hookSecret(env) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("hook:" + (env.SETUP_KEY || "")));
  return hex(d).slice(0, 48);
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}
function text(s, status = 200) {
  return new Response(s, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}
function cors(res) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type");
  h.set("Access-Control-Max-Age", "86400");
  return new Response(res.body, { status: res.status, headers: h });
}
