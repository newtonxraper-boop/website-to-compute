{
  "name": "ai-hub",
  "version": "1.0.0",
  "type": "module",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "express": "^4.19.2",
    "express-rate-limit": "^7.4.0",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2"
  }
}
JWT_SECRET=change_me
PREMIUM_CODE=my-premium
/*
  AI Single-File App — Improved & Secure
  --------------------------------------
  • One-file Node/Express app that serves its own frontend
  • Email/password auth with bcrypt + JWT sessions
  • Helmet + rate limiting for baseline security
  • Premium unlock via env PREMIUM_CODE (30 days)
  • Simple 2D "AI" image endpoint (seeded placeholder) to demo flow
  • 3D viewer via Three.js CDN in the inline frontend

  Quick start:
  1) npm i express helmet express-rate-limit bcryptjs jsonwebtoken
  2) export JWT_SECRET="change_me"  # on Windows: set JWT_SECRET=change_me
     export PREMIUM_CODE="my-premium"  # optional; leave empty to disable code unlock
  3) node server.js  (or: node ./<this file name>)
  4) open http://localhost:3000
*/

import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// --- Config ---
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const PREMIUM_CODE = process.env.PREMIUM_CODE || '';

// --- Middleware ---
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { ok: false, msg: 'Too many requests, slow down.' },
  })
);

// --- In-memory stores (demo only; replace with DB in production) ---
const users = new Map(); // email -> { email, passwordHash, premiumUntil: number|null }
const sessions = new Map(); // token -> email

// --- Helpers ---
async function hash(password) {
  return await bcrypt.hash(password, 10);
}
async function verify(password, passwordHash) {
  return await bcrypt.compare(password, passwordHash);
}
function sign(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, msg: 'Missing token' });
  try {
    const { email } = jwt.verify(token, JWT_SECRET);
    const active = sessions.get(token);
    if (!active || active !== email) throw new Error('Invalid session');
    req.email = email;
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, msg: 'Invalid or expired token' });
  }
}
function now() {
  return Date.now();
}
function addDays(days) {
  return now() + days * 24 * 60 * 60 * 1000;
}

// --- Auth routes ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, msg: 'Email & password required' });
    if (users.has(email)) return res.status(400).json({ ok: false, msg: 'User already exists' });
    const passwordHash = await hash(password);
    users.set(email, { email, passwordHash, premiumUntil: null });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, msg: 'Register failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const u = users.get(email);
    if (!u || !(await verify(password, u.passwordHash))) {
      return res.status(401).json({ ok: false, msg: 'Invalid credentials' });
    }
    const token = sign(email);
    sessions.set(token, email);
    return res.json({ ok: true, token, user: { email, premiumUntil: u.premiumUntil } });
  } catch (e) {
    return res.status(500).json({ ok: false, msg: 'Login failed' });
  }
});

app.get('/api/auth/me', (req, res) => {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false });
  try {
    const { email } = jwt.verify(token, JWT_SECRET);
    const active = sessions.get(token);
    if (!active || active !== email) return res.status(401).json({ ok: false });
    const u = users.get(email);
    return res.json({ ok: true, user: { email, premiumUntil: u?.premiumUntil || null } });
  } catch {
    return res.status(401).json({ ok: false });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (token) sessions.delete(token);
  return res.json({ ok: true });
});

// --- Premium via code ---
app.post('/api/premium/code', auth, (req, res) => {
  try {
    const { code } = req.body || {};
    if (!PREMIUM_CODE) return res.status(400).json({ ok: false, msg: 'Premium code feature disabled' });
    const u = users.get(req.email);
    if (!u) return res.status(404).json({ ok: false });
    if (code !== PREMIUM_CODE) return res.status(401).json({ ok: false, msg: 'Wrong code' });
    const extendMs = addDays(30);
    u.premiumUntil = Math.max(u.premiumUntil || 0, now()) + (30 * 24 * 60 * 60 * 1000);
    users.set(req.email, u);
    return res.json({ ok: true, premiumUntil: u.premiumUntil });
  } catch (e) {
    return res.status(500).json({ ok: false, msg: 'Upgrade failed' });
  }
});

// --- Protected user info ---
app.get('/api/user', auth, (req, res) => {
  const u = users.get(req.email);
  if (!u) return res.status(404).json({ ok: false });
  res.json({ ok: true, user: { email: u.email, premiumUntil: u.premiumUntil } });
});

// --- Simple 2D "AI" image endpoint (demo) ---
// Returns a seeded picsum URL pretending as a generated image.
// If premium, it gives a larger size.
app.post('/api/ai/2d', auth, (req, res) => {
  const { prompt = '' } = req.body || {};
  const u = users.get(req.email);
  const isPremium = !!(u?.premiumUntil && u.premiumUntil > now());
  const size = isPremium ? 1024 : 512;
  // simple deterministic seed from prompt
  const seed = Math.abs([...String(prompt)].reduce((a, c) => (a * 33 + c.charCodeAt(0)) | 0, 5381));
  const url = `https://picsum.photos/seed/${seed}/${size}/${size}`;
  return res.json({ ok: true, url, premium: isPremium });
});

// --- Frontend (inline) ---
app.get('/', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AI Hub — 2D/3D Demo</title>
  <style>
    :root { --bg:#0b1020; --card:#111836; --text:#e7ecff; --muted:#9aa7ff; --accent:#6ea8fe; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto; background: radial-gradient(1200px 600px at 10% -10%, #1a2250 0%, #0b1020 50%, #060a18 100%); color: var(--text); }
    header { display:flex; align-items:center; justify-content:space-between; padding:16px 20px; border-bottom: 1px solid #223; backdrop-filter: blur(8px); position:sticky; top:0; background: rgba(6,10,24,0.6); }
    .brand { font-weight:800; letter-spacing:0.5px; }
    .container { max-width: 1100px; margin: 28px auto; padding: 0 16px; }
    .grid { display:grid; grid-template-columns: 1fr; gap:16px; }
    @media(min-width: 960px){ .grid{ grid-template-columns: 320px 1fr; } }
    .card { background: linear-gradient(180deg, rgba(17,24,54,0.9), rgba(14,18,40,0.9)); border:1px solid #1f274a; border-radius: 16px; padding: 16px; box-shadow: 0 10px 30px rgba(0,0,0,.3); }
    input, button { border-radius: 12px; border:1px solid #2b3566; padding: 10px 12px; background:#0e1430; color:var(--text); }
    input { width:100%; margin-bottom:8px; }
    button { cursor:pointer; }
    button.primary { background: linear-gradient(180deg, #2b5fff, #244bdb); border: none; font-weight: 700; }
    .muted { color: var(--muted); font-size: 12px; }
    .row { display:flex; gap:8px; align-items:center; }
    .row > * { flex: 1 1 auto; }
    .pill { display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius:999px; background:#0c1332; border:1px solid #24306b; font-size:12px; }
    .tag { font-size: 12px; color: #b8c4ff; }
    .right { text-align:right; }
    .center { text-align:center; }
    .spacer { height:8px; }
    .big { font-size: 22px; font-weight: 800; letter-spacing: .3px; }
    #viewer { height: 380px; border-radius: 16px; background: #0a0f26; border: 1px solid #1e2650; }
    .imgbox { display:grid; place-items:center; min-height: 380px; border-radius: 16px; background: #070d22; border: 1px solid #1e2650; }
    img.preview { max-width:100%; max-height:360px; border-radius: 12px; }
    .watermark { font-size: 11px; color: #92a3ff; opacity:.7; }
  </style>
</head>
<body>
  <header>
    <div class="brand">AI Hub</div>
    <div class="pill"><span id="status">Signed out</span></div>
  </header>

  <div class="container grid">
    <!-- Left panel: auth & premium -->
    <div class="card">
      <div class="big">Account</div>
      <div class="spacer"></div>
      <input id="email" type="email" placeholder="Email" />
      <input id="password" type="password" placeholder="Password" />
      <div class="row">
        <button id="register">Register</button>
        <button id="login" class="primary">Login</button>
      </div>
      <div class="spacer"></div>
      <div class="row">
        <button id="logout">Logout</button>
        <div class="tag" id="premiumTag">Free</div>
      </div>
      <div class="spacer"></div>
      <div class="row">
        <input id="premiumCode" placeholder="Enter premium code" />
        <button id="redeem">Redeem</button>
      </div>
      <div class="muted" id="msg"></div>
      <div class="spacer"></div>
      <div class="watermark">Serufusa Abubakar</div>
    </div>

    <!-- Right panel: tools -->
    <div class="card">
      <div class="big">2D Image</div>
      <div class="spacer"></div>
      <div class="row">
        <input id="prompt" placeholder="Prompt e.g., neon cyberpunk owl" />
        <button id="gen" class="primary">Generate</button>
      </div>
      <div class="spacer"></div>
      <div class="imgbox"><img id="preview" class="preview" alt="" /></div>

      <div class="spacer"></div>
      <div class="big">3D Viewer</div>
      <div id="viewer"></div>
    </div>
  </div>

  <script type="module">
    const $ = (s) => document.querySelector(s);
    let token = localStorage.getItem('token') || '';

    async function api(path, opts={}){
      const headers = { 'Content-Type': 'application/json' };
      if(token) headers['Authorization'] = 'Bearer ' + token;
      const res = await fetch(path, { ...opts, headers });
      const data = await res.json().catch(()=>({ ok:false, msg:'Bad JSON' }));
      return { status: res.status, ...data };
    }

    async function refreshSession(){
      if(!token) return setSignedOut();
      const r = await api('/api/auth/me');
      if(r.ok){ setSignedIn(r.user); } else { setSignedOut(); }
    }

    function setSignedIn(user){
      $('#status').textContent = user.email;
      const premium = user.premiumUntil && user.premiumUntil > Date.now();
      $('#premiumTag').textContent = premium ? 'Premium' : 'Free';
    }
    function setSignedOut(){
      token = '';
      localStorage.removeItem('token');
      $('#status').textContent = 'Signed out';
      $('#premiumTag').textContent = 'Free';
    }

    // Auth buttons
    $('#register').onclick = async () => {
      const email = $('#email').value.trim();
      const password = $('#password').value;
      const r = await api('/api/auth/register', { method:'POST', body: JSON.stringify({ email, password }) });
      $('#msg').textContent = r.ok ? 'Registered! You can login now.' : (r.msg||'Register failed');
    };

    $('#login').onclick = async () => {
      const email = $('#email').value.trim();
      const password = $('#password').value;
      const r = await api('/api/auth/login', { method:'POST', body: JSON.stringify({ email, password }) });
      if(r.ok){ token = r.token; localStorage.setItem('token', token); setSignedIn(r.user); $('#msg').textContent = 'Logged in!'; }
      else { $('#msg').textContent = r.msg || 'Login failed'; }
    };

    $('#logout').onclick = async () => {
      await api('/api/auth/logout', { method:'POST' });
      setSignedOut();
      $('#msg').textContent = 'Logged out.';
    };

    $('#redeem').onclick = async () => {
      const code = $('#premiumCode').value.trim();
      const r = await api('/api/premium/code', { method:'POST', body: JSON.stringify({ code }) });
      if(r.ok){ $('#msg').textContent = 'Premium unlocked!'; refreshSession(); }
      else { $('#msg').textContent = r.msg || 'Redeem failed'; }
    };

    // 2D image
    $('#gen').onclick = async () => {
      const prompt = $('#prompt').value.trim();
      const r = await api('/api/ai/2d', { method:'POST', body: JSON.stringify({ prompt }) });
      if(r.ok){ $('#preview').src = r.url; $('#msg').textContent = r.premium? 'Generated (premium size).' : 'Generated.'; }
      else { $('#msg').textContent = r.msg || 'Generation failed'; }
    };

    // 3D viewer using Three.js
    import * as THREE from 'https://unpkg.com/three@0.158.0/build/three.module.js';
    let renderer, scene, camera, cube, anim;
    function init3D(){
      const el = document.getElementById('viewer');
      const w = el.clientWidth; const h = el.clientHeight;
      renderer = new THREE.WebGLRenderer({ antialias:true });
      renderer.setSize(w, h);
      el.innerHTML = ''; el.appendChild(renderer.domElement);
      scene = new THREE.Scene();
      scene.background = new THREE.Color(0x0a0f26);
      camera = new THREE.PerspectiveCamera(50, w/h, 0.1, 100);
      camera.position.set(2.2, 1.6, 2.2);
      const light = new THREE.DirectionalLight(0xffffff, 1.0); light.position.set(2,3,4); scene.add(light);
      const amb = new THREE.AmbientLight(0x404040, 1.2); scene.add(amb);
      const geo = new THREE.BoxGeometry(1,1,1);
      const mat = new THREE.MeshStandardMaterial({ metalness:0.6, roughness:0.3 });
      cube = new THREE.Mesh(geo, mat); scene.add(cube);
      const grid = new THREE.GridHelper(10, 10, 0x224488, 0x112244); scene.add(grid);
      function tick(){
        anim = requestAnimationFrame(tick);
        cube.rotation.x += 0.01; cube.rotation.y += 0.014;
        renderer.render(scene, camera);
      }
      tick();
      new ResizeObserver(()=>{
        const w2 = el.clientWidth, h2 = el.clientHeight;
        renderer.setSize(w2, h2);
        camera.aspect = w2/h2; camera.updateProjectionMatrix();
      }).observe(el);
    }
    init3D();

    // Boot
    refreshSession();
  </script>
</body>
</html>`);
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`AI Hub running on http://localhost:${PORT}`);
});

