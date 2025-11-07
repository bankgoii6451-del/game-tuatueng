#!/usr/bin/env bash
set -euo pipefail

# Usage: ./create_and_push.sh <git-remote-url> [target-dir]
# Example: ./create_and_push.sh git@github.com:you/gift-box.git ./gift-box
REMOTE_URL="${1:-}"
TARGET_DIR="${2:-./gift-box}"

if [[ -z "$REMOTE_URL" ]]; then
  echo "Usage: $0 <git-remote-url> [target-dir]"
  echo "Example: $0 git@github.com:you/gift-box.git ./gift-box"
  exit 1
fi

echo "Project target: $TARGET_DIR"
if [[ -d "$TARGET_DIR" && $(ls -A "$TARGET_DIR" 2>/dev/null || true) != "" ]]; then
  read -p "Target exists and not empty. Overwrite files inside $TARGET_DIR? (y/N) " yn
  case "$yn" in
    [Yy]* ) echo "Proceeding...";;
    * ) echo "Aborted."; exit 1;;
  esac
fi

mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

# write files
cat > package.json <<'EOF'
{
  "name": "gift-box-server",
  "version": "1.0.0",
  "description": "Single-file frontend + Node/Express backend for gift links with encrypted JSON file storage.",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "NODE_ENV=development node index.js"
  },
  "keywords": [],
  "author": "",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2"
  }
}
EOF

cat > index.js <<'EOF'
/**
 * index.js
 * Express server + encrypted JSON DB storage (AES-256-GCM).
 *
 * APIs:
 *  - POST /api/register         { phone, password }                 -> { user, token }
 *  - POST /api/login            { phone, password }                 -> { user, token }
 *  - POST /api/gifts            (admin) { type, content }           -> { gift }
 *  - GET  /api/gifts            list gifts (hides content unless claimed or admin)
 *  - POST /api/gifts/:id/claim  { phone, password } (auth)         -> { message, content }
 *  - GET  /api/status
 *
 * Admin-only backup/restore:
 *  - GET  /api/db/encrypted     (admin) download encrypted db file (data/db.enc)
 *  - POST /api/db/decrypted     (admin) { password } -> returns decrypted JSON DB
 *  - POST /api/db/restore       (admin) { password, db } -> replaces DB with provided object
 *
 * Storage: data/db.enc (iv + authTag + ciphertext)
 *
 * Notes:
 *  - First registered user becomes admin.
 *  - Sessions are stored in DB.sessions with random token & expiry.
 *  - For production: set DB_PASSPHRASE env var to a strong passphrase.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

// Config
const DB_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DB_DIR, 'db.enc');
const PASSPHRASE = process.env.DB_PASSPHRASE || 'dev_change_this_passphrase';
const KEY = crypto.scryptSync(PASSPHRASE, 'salt-for-db', 32); // 32 bytes key
const IV_LEN = 12; // AES-GCM IV length
const AUTH_TAG_LEN = 16;

// Ensure data dir exists
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

// Encryption helpers
function encryptJson(obj) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]);
}

function decryptJson(buffer) {
  const iv = buffer.slice(0, IV_LEN);
  const authTag = buffer.slice(IV_LEN, IV_LEN + AUTH_TAG_LEN);
  const ciphertext = buffer.slice(IV_LEN + AUTH_TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

// Simple DB (in-memory, persisted encrypted)
let DB = { users: [], gifts: [], sessions: [] };

function loadDb() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const buf = fs.readFileSync(DB_FILE);
      DB = decryptJson(buf);
      console.log('✅ Database loaded. Users:', DB.users.length, 'Gifts:', DB.gifts.length);
    } else {
      saveDb(); // create initial file
      console.log('ℹ️  New database created.');
    }
  } catch (err) {
    console.error('Failed to load DB (starting with empty). Error:', err.message);
    DB = { users: [], gifts: [], sessions: [] };
    saveDb();
  }
}

function saveDb() {
  try {
    const buf = encryptJson(DB);
    fs.writeFileSync(DB_FILE, buf);
  } catch (err) {
    console.error('Failed to save DB:', err);
  }
}

// Password hashing (scrypt)
function hashPassword(password, salt = null) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash: derived };
}

function verifyPassword(password, salt, hash) {
  try {
    const h = crypto.scryptSync(password, salt, 64).toString('hex');
    const a = Buffer.from(h, 'hex');
    const b = Buffer.from(hash, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// Sessions
function createSession(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  const expires = Date.now() + 1000 * 60 * 60 * 24 * 7; // 7 days
  DB.sessions.push({ token, userId, expires });
  saveDb();
  return token;
}

function findSession(token) {
  if (!token) return null;
  const s = DB.sessions.find(x => x.token === token && x.expires > Date.now());
  return s || null;
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const s = findSession(token);
  if (!s) return res.status(401).json({ error: 'Unauthorized' });
  const user = DB.users.find(u => u.id === s.userId);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  req.user = user;
  req.session = s;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
    next();
  });
}

function sanitizeUser(user) {
  if (!user) return null;
  const { passwordHash, passwordSalt, ...rest } = user;
  return rest;
}

// Initialize DB
loadDb();

// Routes

// Register
app.post('/api/register', (req, res) => {
  const { phone, password } = req.body || {};
  if (!phone || !password) return res.status(400).json({ error: 'phone and password required' });
  if (DB.users.find(u => u.phone === phone)) return res.status(400).json({ error: 'phone already registered' });

  const { salt, hash } = hashPassword(password);
  const id = crypto.randomUUID();
  const isAdmin = DB.users.length === 0; // first user becomes admin
  const user = { id, phone, passwordSalt: salt, passwordHash: hash, isAdmin, createdAt: Date.now() };
  DB.users.push(user);
  saveDb();

  const token = createSession(id);
  res.json({ user: sanitizeUser(user), token, message: isAdmin ? 'First user -> admin' : 'Registered' });
});

// Login
app.post('/api/login', (req, res) => {
  const { phone, password } = req.body || {};
  if (!phone || !password) return res.status(400).json({ error: 'phone and password required' });
  const user = DB.users.find(u => u.phone === phone);
  if (!user) return res.status(400).json({ error: 'invalid credentials' });
  if (!verifyPassword(password, user.passwordSalt, user.passwordHash)) return res.status(400).json({ error: 'invalid credentials' });

  const token = createSession(user.id);
  res.json({ user: sanitizeUser(user), token });
});

// Create gift (admin)
app.post('/api/gifts', requireAdmin, (req, res) => {
  const { type, content } = req.body || {};
  if (!type || !content) return res.status(400).json({ error: 'type and content required' });
  const id = crypto.randomUUID();
  const gift = { id, type, content, createdBy: req.user.id, createdAt: Date.now(), claimedBy: [] };
  DB.gifts.push(gift);
  saveDb();
  res.json({ gift });
});

// List gifts
app.get('/api/gifts', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const session = findSession(token);
  const currentUserId = session ? session.userId : null;

  const out = DB.gifts.map(g => {
    const claimedByYou = currentUserId && g.claimedBy.includes(currentUserId);
    const obj = {
      id: g.id,
      type: g.type,
      createdAt: g.createdAt,
      createdBy: g.createdBy,
      claimedCount: g.claimedBy.length
    };
    if (claimedByYou || (session && DB.users.find(u => u.id === session.userId && u.isAdmin))) {
      obj.content = g.content;
      obj.claimedBy = g.claimedBy;
    }
    return obj;
  });
  res.json(out);
});

// Claim gift
app.post('/api/gifts/:id/claim', requireAuth, (req, res) => {
  const { id } = req.params;
  const { phone, password } = req.body || {};
  if (!phone || !password) return res.status(400).json({ error: 'phone and password required' });

  // Ensure phone matches logged-in user
  if (req.user.phone !== phone) return res.status(403).json({ error: 'phone does not match logged-in user' });
  if (!verifyPassword(password, req.user.passwordSalt, req.user.passwordHash)) return res.status(400).json({ error: 'invalid credentials' });

  const gift = DB.gifts.find(g => g.id === id);
  if (!gift) return res.status(404).json({ error: 'gift not found' });

  if (gift.claimedBy.includes(req.user.id)) {
    return res.status(400).json({ error: 'already claimed', content: gift.content });
  }

  gift.claimedBy.push(req.user.id);
  saveDb();
  res.json({ message: 'claimed', content: gift.content });
});

// Status
app.get('/api/status', (req, res) => {
  res.json({ status: 'ok', users: DB.users.length, gifts: DB.gifts.length });
});

/**
 * Admin backup & restore endpoints
 */

// Download encrypted DB file (admin only)
app.get('/api/db/encrypted', requireAdmin, (req, res) => {
  if (!fs.existsSync(DB_FILE)) return res.status(404).json({ error: 'db file not found' });
  res.setHeader('Content-Disposition', 'attachment; filename="db.enc"');
  res.setHeader('Content-Type', 'application/octet-stream');
  res.sendFile(DB_FILE);
});

// Return decrypted DB JSON (admin only, extra password verification)
app.post('/api/db/decrypted', requireAdmin, (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'password required' });
  // verify password against admin user (req.user is admin)
  if (!verifyPassword(password, req.user.passwordSalt, req.user.passwordHash)) return res.status(403).json({ error: 'invalid password' });
  // Return DB but without passwordHash/passwordSalt
  const safeDb = {
    users: DB.users.map(u => {
      const { passwordHash, passwordSalt, ...rest } = u;
      return rest;
    }),
    gifts: DB.gifts,
    sessions: DB.sessions
  };
  res.json({ db: safeDb });
});

// Restore DB from provided JSON (admin only). Body: { password, db }
app.post('/api/db/restore', requireAdmin, (req, res) => {
  const { password, db } = req.body || {};
  if (!password || !db) return res.status(400).json({ error: 'password and db required' });
  if (!verifyPassword(password, req.user.passwordSalt, req.user.passwordHash)) return res.status(403).json({ error: 'invalid password' });

  // Basic validation: must have arrays for users/gifts/sessions
  if (!Array.isArray(db.users) || !Array.isArray(db.gifts) || !Array.isArray(db.sessions)) {
    return res.status(400).json({ error: 'db must contain users, gifts, sessions arrays' });
  }

  // IMPORTANT: This endpoint expects that provided db.users contain passwordHash and passwordSalt fields.
  // If you exported via /api/db/encrypted you can restore it by uploading decrypted content.
  DB = db;
  saveDb();
  res.json({ message: 'db restored', users: DB.users.length, gifts: DB.gifts.length });
});

// Simple cleanup endpoint (optional) to remove expired sessions (admin)
app.post('/api/admin/cleanup-sessions', requireAdmin, (req, res) => {
  const before = DB.sessions.length;
  DB.sessions = DB.sessions.filter(s => s.expires > Date.now());
  saveDb();
  res.json({ removed: before - DB.sessions.length, remaining: DB.sessions.length });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`🔐 DB file: ${DB_FILE} (encrypted). Set DB_PASSPHRASE env var to change key.`);
});
EOF

# public dir
mkdir -p public
cat > public/index.html <<'EOF'
<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Gift Box (ทรูมันนี่) — Demo</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial;margin:0;background:#f5f7fb;color:#111}
    header{background:#3b82f6;color:white;padding:12px 16px}
    .container{max-width:900px;margin:20px auto;padding:16px;background:white;border-radius:8px;box-shadow:0 6px 18px rgba(2,6,23,0.08)}
    h1{margin:0 0 12px;font-size:20px}
    form{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
    input,select,button,textarea{padding:8px;border:1px solid #d1d5db;border-radius:6px;font-size:14px}
    button{background:#3b82f6;color:white;border:none;cursor:pointer;padding:8px 12px}
    .muted{color:#6b7280;font-size:13px}
    .flex{display:flex;gap:8px;align-items:center}
    .gifts{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
    .gift{border:1px dashed #e5e7eb;padding:12px;border-radius:8px;background:#fbfdff}
    .danger{background:#fee2e2;color:#991b1b}
    .notice{background:#fff7ed;color:#92400e;padding:8px;border-radius:6px}
    small{color:#6b7280}
    .right{margin-left:auto}
    pre{white-space:pre-wrap;background:#0b1220;color:#d1fae5;padding:8px;border-radius:6px;overflow:auto}
  </style>
</head>
<body>
  <header>
    <div style="max-width:900px;margin:0 auto;display:flex;align-items:center;gap:12px">
      <strong>Gift Box — ทรูมันนี่ (Demo)</strong>
      <small class="muted">Single-server demo with encrypted JSON storage</small>
    </div>
  </header>

  <div class="container">
    <h1>บัญชีผู้ใช้</h1>

    <div id="authArea">
      <form id="registerForm">
        <input id="regPhone" placeholder="เบอร์โทร (e.g. 0991234567)" required />
        <input id="regPass" type="password" placeholder="รหัสผ่าน" required />
        <button type="submit">ลงทะเบียน</button>
        <button id="toLogin" type="button">หรือ เข้าสู่ระบบ</button>
      </form>

      <form id="loginForm" style="display:none">
        <input id="loginPhone" placeholder="เบอร์โทร" required />
        <input id="loginPass" type="password" placeholder="รหัสผ่าน" required />
        <button type="submit">เข้าสู่ระบบ</button>
        <button id="toRegister" type="button">หรือ ลงทะเบียน</button>
      </form>

      <div id="userInfo" style="display:none">
        <div class="flex">
          <div>
            <div><strong id="mePhone"></strong> <small id="meBadge" class="muted"></small></div>
            <div class="muted" id="meId"></div>
          </div>
          <div class="right">
            <button id="logoutBtn">ออกจากระบบ</button>
          </div>
        </div>
      </div>
    </div>

    <hr />

    <div id="adminArea" style="display:none">
      <h2>จัดการซองของขวัญ (สำหรับแอดมิน)</h2>
      <form id="giftForm">
        <select id="giftType">
          <option value="link">ลิงก์ (ทรูมันนี่)</option>
          <option value="text">ข้อความ</option>
          <option value="qr">QR (ข้อความ)</option>
        </select>
        <input id="giftContent" placeholder="ใส่ลิงก์หรือข้อความ" style="flex:1" />
        <button type="submit">เพิ่มซอง</button>
      </form>

      <div style="margin-top:8px">
        <button id="downloadEncBtn">ดาวน์โหลด DB (ไฟล์เข้ารหัส)</button>
        <button id="downloadDecBtn">ดาวน์โหลด DB (JSON ถอดรหัสด้วยรหัสแอดมิน)</button>
        <input id="restoreFile" type="file" accept=".json" />
        <button id="restoreBtn">อัพโหลดและกู้คืนจาก JSON</button>
      </div>
    </div>

    <h2>ซองของขวัญที่มี</h2>
    <div id="giftsList" class="gifts"></div>

    <hr />
    <div class="notice">
      วิธีรับ: ให้ล็อกอิน แล้วคลิก "รับ" ข้างซองที่ต้องการ จากนั้นใส่เบอร์และรหัสผ่านที่ลงทะเบียนไว้เพื่อยืนยันตัวตน
    </div>

    <hr />
    <div>
      <h3>Debug / Status</h3>
      <div id="status" class="muted">Loading...</div>
      <pre id="dbg"></pre>
    </div>
  </div>

  <script>
    const apiFetch = (path, opts = {}) => fetch('/api' + path, Object.assign({
      headers: {'Content-Type': 'application/json'},
    }, opts)).then(async r => {
      const txt = await r.text();
      let body = null;
      try { body = JSON.parse(txt); } catch(e) { body = txt; }
      if (!r.ok) throw { status: r.status, body };
      return body;
    });

    let token = localStorage.getItem('gb_token') || null;
    let me = JSON.parse(localStorage.getItem('gb_user') || 'null');

    const registerForm = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');
    const toLogin = document.getElementById('toLogin');
    const toRegister = document.getElementById('toRegister');
    const userInfo = document.getElementById('userInfo');
    const mePhone = document.getElementById('mePhone');
    const meBadge = document.getElementById('meBadge');
    const meId = document.getElementById('meId');
    const logoutBtn = document.getElementById('logoutBtn');
    const adminArea = document.getElementById('adminArea');
    const giftForm = document.getElementById('giftForm');
    const giftsList = document.getElementById('giftsList');
    const statusEl = document.getElementById('status');
    const dbg = document.getElementById('dbg');

    const downloadEncBtn = document.getElementById('downloadEncBtn');
    const downloadDecBtn = document.getElementById('downloadDecBtn');
    const restoreFile = document.getElementById('restoreFile');
    const restoreBtn = document.getElementById('restoreBtn');

    function setAuth(newToken, user) {
      token = newToken;
      me = user;
      if (token) localStorage.setItem('gb_token', token); else localStorage.removeItem('gb_token');
      if (me) localStorage.setItem('gb_user', JSON.stringify(me)); else localStorage.removeItem('gb_user');
      renderAuth();
      loadGifts();
    }

    function renderAuth() {
      const loggedIn = !!token && !!me;
      registerForm.style.display = loggedIn ? 'none' : (loginForm.style.display === 'none' ? 'flex' : 'flex');
      loginForm.style.display = loggedIn ? 'none' : 'none';
      userInfo.style.display = loggedIn ? 'block' : 'none';
      if (loggedIn) {
        mePhone.innerText = me.phone;
        meBadge.innerText = me.isAdmin ? 'แอดมิน' : '';
        meId.innerText = 'id: ' + me.id;
        adminArea.style.display = me.isAdmin ? 'block' : 'none';
      } else {
        adminArea.style.display = 'none';
      }
    }

    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const phone = document.getElementById('regPhone').value.trim();
      const pass = document.getElementById('regPass').value;
      try {
        const res = await apiFetch('/register', { method: 'POST', body: JSON.stringify({ phone, password: pass }) });
        setAuth(res.token, res.user);
        alert(res.message || 'registered');
      } catch (err) {
        alert(err.body?.error || JSON.stringify(err));
      }
    });

    toLogin.addEventListener('click', () => {
      registerForm.style.display = 'none';
      loginForm.style.display = 'flex';
    });

    toRegister.addEventListener('click', () => {
      loginForm.style.display = 'none';
      registerForm.style.display = 'flex';
    });

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const phone = document.getElementById('loginPhone').value.trim();
      const pass = document.getElementById('loginPass').value;
      try {
        const res = await apiFetch('/login', { method: 'POST', body: JSON.stringify({ phone, password: pass }) });
        setAuth(res.token, res.user);
      } catch (err) {
        alert(err.body?.error || JSON.stringify(err));
      }
    });

    logoutBtn.addEventListener('click', () => {
      setAuth(null, null);
    });

    giftForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const type = document.getElementById('giftType').value;
      const content = document.getElementById('giftContent').value.trim();
      if (!content) return alert('กรุณาใส่เนื้อหา');
      try {
        const res = await fetch('/api/gifts', {
          method: 'POST',
          headers: {'Content-Type':'application/json', 'Authorization': 'Bearer ' + token},
          body: JSON.stringify({ type, content })
        }).then(r => r.json().then(b => { if (!r.ok) throw b; return b; }));
        document.getElementById('giftContent').value = '';
        loadGifts();
        alert('เพิ่มซองเรียบร้อย');
      } catch (err) {
        alert(err.error || err.body?.error || JSON.stringify(err));
      }
    });

    async function loadGifts() {
      try {
        const headers = token ? {'Authorization': 'Bearer ' + token} : {};
        const list = await fetch('/api/gifts', { headers }).then(r => r.json());
        renderGifts(list);
        statusEl.innerText = 'Gifts: ' + list.length;
        dbg.innerText = JSON.stringify({ me, token, gifts: list }, null, 2);
      } catch (err) {
        statusEl.innerText = 'Failed to load';
        dbg.innerText = JSON.stringify(err, null, 2);
      }
    }

    function renderGifts(list) {
      giftsList.innerHTML = '';
      list.forEach(g => {
        const el = document.createElement('div');
        el.className = 'gift';
        el.innerHTML = `
          <div><strong>Type:</strong> ${g.type}</div>
          <div><small class="muted">createdAt: ${new Date(g.createdAt).toLocaleString()}</small></div>
          <div><small class="muted">claimed: ${g.claimedCount}</small></div>
        `;
        if (g.content) {
          const c = document.createElement('div');
          c.style.marginTop = '8px';
          if (g.type === 'link') {
            c.innerHTML = `<a href="${escapeHtml(g.content)}" target="_blank">${escapeHtml(g.content)}</a>`;
          } else {
            c.innerText = g.content;
          }
          el.appendChild(c);
        } else {
          const c = document.createElement('div');
          c.style.marginTop = '8px';
          c.innerHTML = `<em class="muted">เนื้อหาจะเปิดเมื่อคุณรับแล้ว</em>`;
          el.appendChild(c);

          const claimForm = document.createElement('form');
          claimForm.style.marginTop = '8px';
          claimForm.innerHTML = `
            <input name="phone" placeholder="เบอร์ที่ลงทะเบียน" style="width:120px" value="${me ? me.phone : ''}" required />
            <input name="pass" type="password" placeholder="รหัสผ่าน" style="width:140px" required />
            <button type="submit">รับ</button>
          `;
          claimForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const phone = form.phone.value.trim();
            const password = form.pass.value;
            try {
              const res = await fetch('/api/gifts/' + g.id + '/claim', {
                method: 'POST',
                headers: {'Content-Type':'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({ phone, password })
              }).then(r => r.json().then(b => { if (!r.ok) throw b; return b; }));
              alert('รับสำเร็จ! เนื้อหา: ' + res.content);
              loadGifts();
            } catch (err) {
              alert(err.error || err.body?.error || JSON.stringify(err));
            }
          });
          el.appendChild(claimForm);
        }
        giftsList.appendChild(el);
      });
    }

    function escapeHtml(s){ return (s+'').replace(/[&<>"']/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])); }

    // Admin: download encrypted DB
    downloadEncBtn.addEventListener('click', async () => {
      if (!confirm('ดาวน์โหลดไฟล์ DB ที่เข้ารหัส? (admin only)')) return;
      try {
        const resp = await fetch('/api/db/encrypted', { headers: { 'Authorization': 'Bearer ' + token } });
        if (!resp.ok) {
          const err = await resp.json().catch(()=>({}));
          throw err;
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'db.enc';
        document.body.appendChild(a);
        a.click();
        a.remove();
      } catch (err) {
        alert(err.error || err.body?.error || JSON.stringify(err));
      }
    });

    // Admin: download decrypted DB (requires admin password)
    downloadDecBtn.addEventListener('click', async () => {
      const pwd = prompt('กรุณาใส่รหัสผ่านแอดมินเพื่อตรวจสอบและดาวน์โหลด DB (JSON):');
      if (!pwd) return;
      try {
        const res = await apiFetch('/db/decrypted'.startsWith('/api')?'/db/decrypted':'/db/decrypted', {
          method: 'POST',
          headers: {'Content-Type':'application/json', 'Authorization': 'Bearer ' + token},
          body: JSON.stringify({ password: pwd })
        });
        const blob = new Blob([JSON.stringify(res.db, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'db.json';
        document.body.appendChild(a);
        a.click();
        a.remove();
      } catch (err) {
        alert(err.error || err.body?.error || JSON.stringify(err));
      }
    });

    // Admin: restore from uploaded JSON file
    restoreBtn.addEventListener('click', async () => {
      if (!restoreFile.files[0]) return alert('เลือกไฟล์ JSON ก่อน');
      const pwd = prompt('กรุณาใส่รหัสผ่านแอดมินเพื่อตรวจสอบก่อนกู้คืน:');
      if (!pwd) return;
      const file = restoreFile.files[0];
      try {
        const text = await file.text();
        const db = JSON.parse(text);
        const res = await apiFetch('/db/restore'.startsWith('/api')?'/db/restore':'/db/restore', {
          method: 'POST',
          headers: {'Content-Type':'application/json', 'Authorization': 'Bearer ' + token},
          body: JSON.stringify({ password: pwd, db })
        });
        alert('กู้คืนสำเร็จ');
        location.reload();
      } catch (err) {
        alert(err.error || err.body?.error || JSON.stringify(err));
      }
    });

    // init
    renderAuth();
    loadGifts();
  </script>
</body>
</html>
EOF

cat > .gitignore <<'EOF'
node_modules
data/*.enc
EOF

cat > Dockerfile <<'EOF'
# Dockerfile (optional)
FROM node:18-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --only=production || npm install
COPY . .
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "index.js"]
EOF

# README (use four backticks for markdown file)
cat > README.md <<'README_EOF'
# Gift Box — Node + Single-page Frontend (พร้อมใช้งาน)

โครงงานนี้เป็นตัวอย่างระบบ "รับของขวัญ" แบบพร้อมใช้งาน:
- Frontend: public/index.html (UI ลงทะเบียน/ล็อกอิน, เพิ่มซอง, รับซอง)
- Backend: index.js (Express) — เก็บข้อมูลในไฟล์ data/db.enc แบบเข้ารหัส (AES-256-GCM)
- การเข้ารหัส DB ใช้คีย์ที่สกัดจาก environment variable DB_PASSPHRASE (ตั้งค่าเพื่อความปลอดภัย)

คุณสมบัติสำคัญ:
- ลงทะเบียน/ล็อกอินด้วยเบอร์โทร + รหัสผ่าน
- First registered user -> admin (สามารถเพิ่มซองและดาวน์โหลด/กู้คืน DB)
- แอดมินเพิ่มซองได้ (type: link/text/qr)
- ผู้เล่นล็อกอินแล้วสามารถ "รับ" ซองโดยยืนยันเบอร์ + รหัสผ่าน
- รหัสผ่านถูก hash ด้วย scrypt
- ข้อมูลในดิสก์ถูกเข้ารหัสด้วย AES-256-GCM

การติดตั้งและรัน (บนเครื่องของคุณ):
1. ติดตั้ง dependencies:
   npm install

2. (แนะนำ) ตั้งค่า passphrase สำหรับ DB:
   สำหรับ macOS / Linux:
     export DB_PASSPHRASE="your-very-strong-passphrase"
   Windows (Powershell):
     $env:DB_PASSPHRASE="your-very-strong-passphrase"

   ถ้าไม่ตั้ง ระบบจะใช้ค่าเริ่มต้น 'dev_change_this_passphrase'

3. เริ่มเซิร์ฟเวอร์:
   npm start

4. เปิดเบราว์เซอร์:
   http://localhost:3000

การใช้งานด่วน:
- ลงทะเบียนผู้ใช้แรก -> จะกลายเป็นแอดมิน
- แอดมินเพิ่มซอง (ลิงก์ทรูมันนี่หรือข้อความ)
- ผู้เล่นล็อกอิน -> คลิก "รับ" และยืนยันเบอร์+รหัสผ่าน ผู้เล่นรับได้ครั้งเดียว/คน

Backup & Restore (สำหรับแอดมิน):
- ดาวน์โหลดไฟล์ DB ที่เข้ารหัส (data/db.enc):
  GET /api/db/encrypted  (ต้องส่ง Authorization: Bearer <token> ของแอดมิน)
  ตัวอย่าง:
    curl -H "Authorization: Bearer <token>" -o db.enc "http://localhost:3000/api/db/encrypted"

- ดาวน์โหลด DB แบบ JSON (ถอดรหัส) — ต้องยืนยันรหัสแอดมิน:
  POST /api/db/decrypted  Content-Type: application/json
    body: { "password": "admin-password" }
  ตัวอย่าง:
    curl -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"password":"..."}' "http://localhost:3000/api/db/decrypted"

- กู้คืน DB (restore) — ส่ง JSON ของ DB (ต้องมี passwordHash/passwordSalt ถ้านำกลับมา):
  POST /api/db/restore  Content-Type: application/json
    body: { "password": "admin-password", "db": { ... } }

คำเตือนด้านความปลอดภัย:
- นี่เป็นตัวอย่างเดโม ไม่เหมาะสำหรับ production โดยตรง
- แนะนำอย่างยิ่งให้:
  - เปลี่ยน DB_PASSPHRASE เป็นค่าแข็งแรง
  - ใช้ HTTPS, rate limiting และ input validation เพิ่มเติม
  - จัดการ session expiration/cleanup เป็นประจำ
README_EOF

echo "Files written to $(pwd)."
echo ""
echo "Next steps:"
echo "1) cd $TARGET_DIR"
echo "2) npm install"
echo "3) (optional) export DB_PASSPHRASE='your-passphrase'"
echo "4) npm start"
echo ""
echo "Now committing & pushing to remote: $REMOTE_URL"
if [[ ! -d .git || ! -f .git/config ]]; then
  git init
fi
git add -A
git commit -m "Initial commit: Gift Box project" || true
git branch -M main 2>/dev/null || true

# set remote
if git remote | grep -q "^origin$"; then
  echo "Remote origin exists. Updating origin to $REMOTE_URL"
  git remote remove origin
fi
git remote add origin "$REMOTE_URL"
echo "Pushing to remote (may ask for credentials)..."
git push -u origin main

echo "Done. If push failed, check credentials/remote URL and try:"
echo "  git remote set-url origin <your-remote>"
echo "  git push -u origin main"