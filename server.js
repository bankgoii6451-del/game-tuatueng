// server.js
// Single-file redirect server + embedded frontend
// Run: node server.js
// Note: For production use HTTPS + reverse proxy (nginx) and secure storage for redirectMap.

const http = require('http');
const url = require('url');

// --- Config ---
const PORT = process.env.PORT || 3000;
const HOSTNAME = '0.0.0.0'; // change if needed

// Simple in-memory redirect map (KEEP THIS PRIVATE ON THE SERVER)
const redirectMap = {
  // games
  k1: 'http://www.th34222.com/?r=bzu8899',
  k2: 'http://www.mb661011.net/?r=gnv5085',
  k3: 'http://www.new882211.vip/?r=ioc2383',
  k4: 'http://www.78112277.com/?r=vzg7691',
  k5: 'https://7893232.com/?r=N683RY',
  k6: 'https://www.f162288.cc/?id=262423264',
  k7: 'https://www.mk81122.com/?af=X7T7JD',
  k8: 'http://www.pg68833.xyz/?r=nko0130',
  k9: 'https://www.jun8896.com/?af=PS47AC',
  k10: 'http://www.vg981188.vip/?r=zuk5265',
  k11: 'http://yaoqing.77777vip9.com/?referralCode=jxd7503',
  // socials
  s1: 'https://t.me/Pe_King0',
  s2: 'https://www.tiktok.com/@tgxpm_i5?_t=ZS-90sZSAevDj0&_r=1',
  s3: 'https://x.com/TGXPM_I5?s=09',
  s4: 'https://www.instagram.com/tgxpm_i5?igsh=bHF0YTIzeWdxczBp',
  s5: 'https://www.facebook.com/share/1ZRMKJqF7P/',
  s6: 'https://t.me/xxxgoii'
};

// --- Basic rate limiting (per-IP, rolling window) ---
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 60s
const RATE_LIMIT_MAX = 120; // max requests per window per IP
const ipHits = new Map(); // ip -> array of timestamps

function checkRateLimit(ip) {
  const now = Date.now();
  if (!ipHits.has(ip)) ipHits.set(ip, []);
  const arr = ipHits.get(ip);
  // drop old entries
  while (arr.length && arr[0] <= now - RATE_LIMIT_WINDOW_MS) arr.shift();
  if (arr.length >= RATE_LIMIT_MAX) return false;
  arr.push(now);
  return true;
}

// --- Security headers ---
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // CSP - minimal, allow same origin scripts/styles; adjust if needed
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data:;");
}

// --- Embedded HTML (frontend) ---
const pageHTML = `<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>GPT ตัวตึง — Neon Portal (Server Redirect)</title>
<link href="https://fonts.googleapis.com/css2?family=Kanit:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>
:root{--bg1:#05030a;--bg2:#0b0b1a;--neon:#00d0ff;--accent:#6a00ff;--muted:#98a0b3;}
html,body{height:100%}
body{margin:0;font-family:'Kanit',sans-serif;background:
  radial-gradient(1200px 600px at 10% 10%, rgba(0,208,255,0.06), transparent),
  radial-gradient(900px 400px at 90% 90%, rgba(106,0,255,0.05), transparent),
  linear-gradient(180deg,var(--bg1),var(--bg2));
  color:#e6f7ff; -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; overflow-x:hidden;}
.container{max-width:1100px;margin:48px auto;padding:24px}
header{display:flex;align-items:center;gap:16px}
.logo{width:64px;height:64px;border-radius:14px;background:linear-gradient(135deg, rgba(0,208,255,0.12), rgba(106,0,255,0.12));display:grid;place-items:center;border:1px solid rgba(0,208,255,0.18)}
.title{font-weight:800;font-size:20px}
.subtitle{color:var(--muted);font-size:13px}
.links-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px;margin-top:28px}
.card{background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));border-radius:12px;padding:14px;border:1px solid rgba(255,255,255,0.04)}
.neon-btn{display:inline-flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;background:linear-gradient(90deg, rgba(0,208,255,0.06), rgba(106,0,255,0.06));border:1px solid rgba(0,208,255,0.18);cursor:pointer;font-weight:700}
.badge{background:linear-gradient(90deg,var(--neon),var(--accent));padding:6px 8px;border-radius:8px;color:#00101a;font-weight:800;font-size:12px}
.controls{display:flex;gap:12px;margin-left:auto}
.icon-btn{padding:8px;border-radius:10px;border:1px solid rgba(255,255,255,0.04);background:transparent;cursor:pointer}
.overlay{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:28px;background:linear-gradient(180deg, rgba(2,2,6,0.6), rgba(2,2,6,0.85));backdrop-filter:blur(6px);opacity:0;pointer-events:none;transition:opacity .22s ease}
.overlay.open{opacity:1;pointer-events:auto}
.modal{width:100%;max-width:720px;background:linear-gradient(180deg, rgba(10,8,20,0.7), rgba(6,4,12,0.9));padding:18px;border-radius:12px;border:1px solid rgba(255,255,255,0.04)}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
footer{margin-top:28px;text-align:center;color:var(--muted);font-size:13px}
@media (max-width:640px){.links-grid{grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}}
</style>
</head>
<body>
<main class="container">
  <header>
    <div class="logo">GPT</div>
    <div>
      <div class="title">GPT ตัวตึง — Neon Portal</div>
      <div class="subtitle">Server-side redirect — ลิงก์ไม่ปรากฏใน HTML</div>
    </div>
    <div class="controls">
      <button class="icon-btn" id="openSocials">โซเชียล</button>
      <button class="icon-btn" id="muteToggle">ปิดเสียง</button>
    </div>
  </header>

  <section class="links-grid" aria-label="ลิงก์เว็บเกม">
    <!-- Buttons reference server keys only -->
    <article class="card"><h3>TH39</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k1"><span>เปิดเว็บ</span><span class="badge">TH39</span></button></div></article>
    <article class="card"><h3>MB66</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k2"><span>เปิดเว็บ</span><span class="badge">MB66</span></button></div></article>
    <article class="card"><h3>NEW88</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k3"><span>เปิดเว็บ</span><span class="badge">NEW88</span></button></div></article>
    <article class="card"><h3>78win</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k4"><span>เปิดเว็บ</span><span class="badge">78win</span></button></div></article>
    <article class="card"><h3>789bet</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k5"><span>เปิดเว็บ</span><span class="badge">789bet</span></button></div></article>
    <article class="card"><h3>F168</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k6"><span>เปิดเว็บ</span><span class="badge">F168</span></button></div></article>
    <article class="card"><h3>MK8</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k7"><span>เปิดเว็บ</span><span class="badge">MK8</span></button></div></article>
    <article class="card"><h3>PG68</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k8"><span>เปิดเว็บ</span><span class="badge">PG68</span></button></div></article>
    <article class="card"><h3>jun88</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k9"><span>เปิดเว็บ</span><span class="badge">jun88</span></button></div></article>
    <article class="card"><h3>VG98</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k10"><span>เปิดเว็บ</span><span class="badge">VG98</span></button></div></article>
    <article class="card"><h3>777GAME</h3><p>เปิดเว็บ</p><div style="margin-top:12px"><button class="neon-btn openKey" data-key="k11"><span>เปิดเว็บ</span><span class="badge">777GAME</span></button></div></article>
  </section>

  <footer><small>ออกแบบโดย GPT • Redirect server</small></footer>
</main>

<!-- Social overlay -->
<div class="overlay" id="socialOverlay" aria-hidden="true">
  <div class="modal" role="dialog" aria-modal="true">
    <div style="display:flex;align-items:center;gap:12px">
      <div style="width:48px;height:48px;border-radius:10px;background:linear-gradient(90deg,var(--neon),var(--accent));display:grid;place-items:center;color:#00101a;font-weight:800">SG</div>
      <div><div style="font-weight:800">Socials — ช่องทางติดต่อ</div><div style="color:var(--muted);font-size:13px">Telegram, TikTok, X, Instagram, Facebook, กลุ่ม 18+</div></div>
      <div style="margin-left:auto"><button class="neon-btn" id="closeOverlay">ปิด</button></div>
    </div>
    <div class="row" style="margin-top:12px">
      <button class="neon-btn openKey" data-key="s1"><span>Telegram</span><span class="badge">TG</span></button>
      <button class="neon-btn openKey" data-key="s2"><span>TikTok</span><span class="badge">TT</span></button>
      <button class="neon-btn openKey" data-key="s3"><span>X / Twitter</span><span class="badge">X</span></button>
      <button class="neon-btn openKey" data-key="s4"><span>Instagram</span><span class="badge">IG</span></button>
      <button class="neon-btn openKey" data-key="s5"><span>Facebook</span><span class="badge">FB</span></button>
      <button class="neon-btn openKey" data-key="s6"><span>กลุ่ม 18+</span><span class="badge">18+</span></button>
    </div>
  </div>
</div>

<script>
/* Frontend: opens server endpoint /r/{key} in new tab.
   Uses WebAudio API to generate a short click sound (no file needed).
*/
const clickOsc = (() => {
  // returns a function playClick() that safely plays a short click
  let ctx = null;
  return () => {
    if (!ctx) {
      try { ctx = new (window.AudioContext || window.webkitAudioContext)(); } catch(e){ ctx = null; }
    }
    if (!ctx) return;
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.type = 'sine';
    o.frequency.value = 900;
    g.gain.value = 0;
    o.connect(g); g.connect(ctx.destination);
    // short envelope
    const now = ctx.currentTime;
    g.gain.cancelScheduledValues(now);
    g.gain.setValueAtTime(0, now);
    g.gain.linearRampToValueAtTime(0.15, now + 0.005);
    g.gain.exponentialRampToValueAtTime(0.001, now + 0.06);
    o.start(now);
    o.stop(now + 0.07);
  };
})();

let soundOn = true;
document.getElementById('muteToggle').addEventListener('click', () => {
  soundOn = !soundOn;
  document.getElementById('muteToggle').textContent = soundOn ? 'ปิดเสียง' : 'เปิดเสียง';
});

// open redirect endpoint
function openKey(key) {
  const endpoint = '/r/' + encodeURIComponent(key);
  if (soundOn) try { clickOsc(); } catch(e){}
  window.open(endpoint, '_blank', 'noopener');
}

// bind buttons
document.querySelectorAll('.openKey').forEach(b => {
  b.addEventListener('click', (e) => {
    const k = b.dataset.key;
    openKey(k);
  });
});

// overlay controls
const overlay = document.getElementById('socialOverlay');
document.getElementById('openSocials').addEventListener('click', () => { overlay.classList.add('open'); overlay.setAttribute('aria-hidden','false'); if (soundOn) try { clickOsc(); } catch(e){} });
document.getElementById('closeOverlay').addEventListener('click', () => { overlay.classList.remove('open'); overlay.setAttribute('aria-hidden','true'); if (soundOn) try { clickOsc(); } catch(e){} });
overlay.addEventListener('click', (e) => { if (e.target === overlay) { overlay.classList.remove('open'); overlay.setAttribute('aria-hidden','true'); }});
document.addEventListener('keydown', e => { if (e.key === 'Escape') { overlay.classList.remove('open'); overlay.setAttribute('aria-hidden','true'); } });
</script>
</body>
</html>`;

// --- HTTP server ---
const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || '/';
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

  // basic rate limit check
  if (!checkRateLimit(ip)) {
    res.statusCode = 429;
    setSecurityHeaders(res);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('Too many requests');
    return;
  }

  // Serve index
  if (pathname === '/' || pathname === '/index.html') {
    setSecurityHeaders(res);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(pageHTML);
    return;
  }

  // Redirect endpoint: /r/:key
  // allow both /r/key and /r/key/
  if (pathname.startsWith('/r/')) {
    const parts = pathname.split('/');
    const key = parts[2] || '';
    if (!key) {
      res.statusCode = 400;
      setSecurityHeaders(res);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.end('Bad request (missing key)');
      return;
    }

    const target = redirectMap[key];
    if (!target) {
      res.statusCode = 404;
      setSecurityHeaders(res);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.end('Not found');
      return;
    }

    // Optional: log click (time, key, ip, ua)
    const ua = req.headers['user-agent'] || '';
    console.log(new Date().toISOString(), 'redirect', key, '->', target, ip, ua);

    // perform redirect (302)
    res.statusCode = 302;
    setSecurityHeaders(res);
    res.setHeader('Location', target);
    res.end();
    return;
  }

  // Unknown path -> 404
  res.statusCode = 404;
  setSecurityHeaders(res);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end('Not found');
});

server.listen(PORT, HOSTNAME, () => {
  console.log(\`Server running at http://\${HOSTNAME}:\${PORT}/\`);
  console.log('Keys available:', Object.keys(redirectMap).join(', '));
});
