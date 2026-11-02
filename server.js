// ROBX online server: accounts + data + friends + rooms, zero dependencies (Node >= 18).
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_FILE || path.join(__dirname, "data.json");
const ADMINS = (process.env.ADMIN_NAMES || "TRK_pro1000y7").split(",").map(s => s.trim().toLowerCase());
const MAXP = 16;
let db = { users: {}, tokens: {}, docs: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DATA, "utf8"))); } catch (e) {}
let dirty = false;
function flush() { if (!dirty) return; dirty = false; try { fs.writeFileSync(DATA + ".tmp", JSON.stringify(db)); fs.renameSync(DATA + ".tmp", DATA); } catch (e) { console.error("save failed", e.message); dirty = true; } }
setInterval(flush, 3000);
for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => { flush(); process.exit(0); });

const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 32, (e, k) => e ? rej(e) : res(k)));
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const isAdmin = name => ADMINS.includes(String(name).toLowerCase());
const authRate = new Map();
function rateOk(ip) { const n = Date.now(), r = authRate.get(ip) || { n: 0, t: n }; if (n - r.t > 60000) { r.n = 0; r.t = n; } r.n++; authRate.set(ip, r); return r.n <= 12; }

/* ---------- permissions ---------- */
const PUBLIC = ["players", "pub", "srv", "req", "lk"];
function canRead(c, p) { const a = p.split("/"); if (a[0] === "data" && a[1] === "users") return a[2] === c.uid; if (a[0] === "rep") return a[1] === c.uid || c.admin; return PUBLIC.includes(a[0]); }
function canWrite(c, p) { const a = p.split("/"); if (a[0] === "data" && a[1] === "users") return a[2] === c.uid && a.length === 4; return [...PUBLIC, "rep"].includes(a[0]) && a.length === 2 && a[1] === c.uid; }
const validPath = p => typeof p === "string" && p.length < 200 && /^[A-Za-z0-9_\-\/]+$/.test(p) && !p.includes("//");

/* ---------- collections & subscriptions ---------- */
const clients = new Set(), rooms = new Map(), snapTimers = {};
function listColl(c) { const out = [], pre = c + "/"; for (const k in db.docs) if (k.startsWith(pre) && k.indexOf("/", pre.length) < 0) out.push({ id: k.slice(pre.length), data: db.docs[k] }); return out; }
function pushSnap(c) { if (snapTimers[c]) return; snapTimers[c] = setTimeout(() => { delete snapTimers[c]; const docs = listColl(c); for (const cl of clients) if (cl.subs.has(c)) cl.send({ ev: "snap", c, docs }); }, 150); }
function setDoc(c, p, v) {
  const a = p.split("/");
  if (a[0] === "players") v = { name: c.name, gender: c.gender };
  else if (a[0] === "pub") v.owner = c.name;
  else if (a[0] === "srv") v.n = c.name;
  db.docs[p] = v; dirty = true; if (a.length === 2) pushSnap(a[0]);
}
function delDoc(p) { if (p in db.docs) { delete db.docs[p]; dirty = true; const a = p.split("/"); if (a.length === 2) pushSnap(a[0]); } }

/* ---------- rooms ---------- */
function roomPush(name) {
  const r = rooms.get(name); if (!r || r.t) return;
  r.t = setTimeout(() => { r.t = null; const list = [...r.m.values()];
    for (const me of list) me.send({ ev: "peers", peers: list.map(o => ({ peer: o.peer, isMe: o === me, kind: "viewer", presence: o.presence || {} })) }); }, 50);
}
function leaveRoom(c) { if (!c.room) return; const r = rooms.get(c.room); if (r) { r.m.delete(c.peer); if (!r.m.size) rooms.delete(c.room); else roomPush(c.room); } c.room = null; }

/* ---------- ops ---------- */
async function session(c, u, ip) {
  const token = crypto.randomBytes(24).toString("hex"); db.tokens[sha(token)] = u.uid; dirty = true;
  c.uid = u.uid; c.name = u.name; c.gender = u.gender; c.admin = isAdmin(u.name);
  return { uid: u.uid, token, name: u.name, gender: u.gender, joined: u.joined, admin: c.admin };
}
const ops = {
  async reg(c, m) {
    if (!rateOk(c.ip)) throw new Error("ลองบ่อยเกินไป รอสักครู่");
    const name = String(m.name || "").trim(), pw = String(m.pw || ""), g = m.gender === "f" ? "f" : m.gender === "m" ? "m" : null;
    if (!/^[\p{L}\p{N}_-]{3,16}$/u.test(name)) throw new Error("ชื่อต้องยาว 3–16 ตัว ใช้ตัวอักษร ตัวเลข _ - เท่านั้น");
    if (pw.length < 6 || pw.length > 100) throw new Error("รหัสผ่านต้องมี 6–100 ตัว");
    if (!g) throw new Error("กรุณาเลือกเพศ");
    if (Object.values(db.users).some(u => u.name.toLowerCase() === name.toLowerCase())) throw new Error("ชื่อนี้ถูกใช้แล้ว");
    const salt = crypto.randomBytes(16).toString("hex"), uid = crypto.randomBytes(8).toString("hex");
    const u = { uid, name, gender: g, salt, hash: (await scrypt(pw, salt)).toString("hex"), joined: Date.now() };
    db.users[uid] = u; db.docs["players/" + uid] = { name, gender: g }; dirty = true; pushSnap("players");
    return session(c, u);
  },
  async login(c, m) {
    if (!rateOk(c.ip)) throw new Error("ลองบ่อยเกินไป รอสักครู่");
    const name = String(m.name || "").trim().toLowerCase(), u = Object.values(db.users).find(x => x.name.toLowerCase() === name);
    const bad = new Error("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง");
    if (!u) throw bad;
    const h = await scrypt(String(m.pw || ""), u.salt);
    if (!crypto.timingSafeEqual(h, Buffer.from(u.hash, "hex"))) throw bad;
    return session(c, u);
  },
  async resume(c, m) { const uid = db.tokens[sha(String(m.token || ""))], u = uid && db.users[uid]; if (!u) throw new Error("เซสชันหมดอายุ"); c.uid = u.uid; c.name = u.name; c.gender = u.gender; c.admin = isAdmin(u.name); return { uid: u.uid, name: u.name, gender: u.gender, joined: u.joined, admin: c.admin }; },
  async logout(c, m) { if (m.token) { delete db.tokens[sha(String(m.token))]; dirty = true; } cleanup(c); c.uid = null; return {}; },
  async get(c, m) { need(c); if (!validPath(m.p) || !canRead(c, m.p)) throw new Error("ไม่มีสิทธิ์อ่าน"); const d = db.docs[m.p]; return d ? { exists: true, data: d } : { exists: false }; },
  async set(c, m) {
    need(c); if (!validPath(m.p) || !canWrite(c, m.p)) throw new Error("ไม่มีสิทธิ์เขียน");
    if (!m.v || typeof m.v !== "object" || Array.isArray(m.v)) throw new Error("ข้อมูลไม่ถูกต้อง");
    if (JSON.stringify(m.v).length > 250000) throw new Error("ข้อมูลใหญ่เกินไป");
    setDoc(c, m.p, m.v); return {};
  },
  async del(c, m) { need(c); if (!validPath(m.p) || !canWrite(c, m.p)) throw new Error("ไม่มีสิทธิ์ลบ"); delDoc(m.p); return {}; },
  async sub(c, m) { need(c); const k = String(m.c); if (!(PUBLIC.includes(k) || (k === "rep" && c.admin))) throw new Error("ไม่มีสิทธิ์"); c.subs.add(k); return { docs: listColl(k) }; },
  async join(c, m) {
    need(c); const name = String(m.r || ""); if (!/^[a-z0-9][a-z0-9_.-]{0,47}$/.test(name)) throw new Error("ชื่อห้องไม่ถูกต้อง");
    leaveRoom(c); let r = rooms.get(name); if (!r) { r = { m: new Map(), t: null }; rooms.set(name, r); }
    if (r.m.size >= MAXP) throw new Error("เซิร์ฟเวอร์เต็ม");
    c.room = name; c.peer = crypto.randomBytes(4).toString("hex"); c.presence = null; r.m.set(c.peer, c); roomPush(name); return { peer: c.peer };
  },
  async leave(c) { leaveRoom(c); return {}; },
  async presence(c, m) {
    if (!c.room || !m.v || typeof m.v !== "object" || JSON.stringify(m.v).length > 1500) return;
    const v = m.v; for (const k of ["x", "y", "z"]) if (typeof v[k] === "number") v[k] = Math.max(-5000, Math.min(5000, v[k]));
    v.n = c.name; v.u = c.uid; v.g = c.gender; c.presence = v; roomPush(c.room);
  },
  async emit(c, m) {
    need(c); if (!c.room || m.t !== "chat" || !m.v || typeof m.v.t !== "string") throw new Error("ส่งไม่ได้");
    const now = Date.now(); c.chatT = (c.chatT || []).filter(t => now - t < 5000); if (c.chatT.length >= 6) throw new Error("ส่งแชตถี่เกินไป");
    c.chatT.push(now);
    const text = m.v.t.replace(/[\u0000-\u001f]/g, "").slice(0, 120); if (!text.trim()) return {};
    const r = rooms.get(c.room); if (r) for (const o of r.m.values()) o.send({ ev: "msg", t: "chat", d: { n: c.name, u: c.uid, t: text } });
    return {};
  }
};
function need(c) { if (!c.uid) throw new Error("ต้องเข้าสู่ระบบ"); }
function cleanup(c) { leaveRoom(c); if (c.uid) delDoc("srv/" + c.uid); c.subs.clear(); }

/* ---------- WebSocket (RFC 6455 minimal) ---------- */
class Conn {
  constructor(s, ip) { this.s = s; this.ip = ip; this.buf = Buffer.alloc(0); this.frag = []; this.subs = new Set(); this.uid = null; this.room = null; this.cnt = 0; this.ct = Date.now();
    s.on("data", d => this.onData(d)); s.on("close", () => this.onClose()); s.on("error", () => {}); }
  onData(d) {
    this.buf = Buffer.concat([this.buf, d]); if (this.buf.length > 2e6) return this.close();
    for (;;) {
      const b = this.buf; if (b.length < 2) return;
      const fin = b[0] & 128, op = b[0] & 15, masked = b[1] & 128; let len = b[1] & 127, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; } else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
      if (!masked || len > 1e6) return this.close();
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4), p = Buffer.from(b.subarray(off + 4, off + 4 + len)); for (let i = 0; i < len; i++) p[i] ^= mask[i & 3];
      this.buf = b.subarray(off + 4 + len);
      if (op === 8) return this.close(); if (op === 9) { this.raw(10, p); continue; } if (op === 10) continue;
      if (op === 1 || op === 2) this.frag = [p]; else if (op === 0) this.frag.push(p); else continue;
      if (fin) { const m = Buffer.concat(this.frag).toString("utf8"); this.frag = []; this.onMsg(m); }
    }
  }
  raw(op, p) { if (this.s.destroyed) return; const l = p.length; let h; if (l < 126) h = Buffer.from([128 | op, l]); else if (l < 65536) { h = Buffer.alloc(4); h[0] = 128 | op; h[1] = 126; h.writeUInt16BE(l, 2); } else { h = Buffer.alloc(10); h[0] = 128 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(l), 2); } this.s.write(Buffer.concat([h, p])); }
  send(o) { this.raw(1, Buffer.from(JSON.stringify(o))); }
  close() { try { this.raw(8, Buffer.alloc(0)); this.s.end(); } catch (e) {} }
  onClose() { clients.delete(this); cleanup(this); }
  async onMsg(str) {
    const n = Date.now(); if (n - this.ct > 1000) { this.ct = n; this.cnt = 0; } if (++this.cnt > 150) return;
    let m; try { m = JSON.parse(str); } catch (e) { return; }
    const f = ops[m && m.op]; if (!f) { if (m && m.i) this.send({ i: m.i, ok: false, e: "ไม่รู้จักคำสั่ง" }); return; }
    try { const d = await f(this, m); if (m.i) this.send({ i: m.i, ok: true, d: d || {} }); }
    catch (e) { if (m.i) this.send({ i: m.i, ok: false, e: e.message || "ผิดพลาด" }); }
  }
}

/* ---------- HTTP ---------- */
const INDEX = path.join(__dirname, "public", "index.html");
const server = http.createServer((req, res) => {
  if (req.url === "/health") { res.writeHead(200, { "content-type": "text/plain" }); return res.end("ok"); }
  if (req.url === "/manifest.webmanifest") { res.writeHead(200, { "content-type": "application/manifest+json" }); return res.end(JSON.stringify({ name: "ROBX", short_name: "ROBX", start_url: "/", display: "fullscreen", orientation: "any", background_color: "#10131c", theme_color: "#10131c" })); }
  fs.readFile(INDEX, (e, d) => { if (e) { res.writeHead(500); return res.end("index.html missing"); } res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache" }); res.end(d); });
});
server.on("upgrade", (req, socket) => {
  const key = req.headers["sec-websocket-key"];
  if (!key || String(req.headers.upgrade).toLowerCase() !== "websocket") return socket.destroy();
  socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64") + "\r\n\r\n");
  const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress).split(",")[0].trim();
  const c = new Conn(socket, ip); clients.add(c);
});
server.listen(PORT, () => console.log("ROBX server on :" + PORT));
