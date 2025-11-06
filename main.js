/* main.js — frontend logic for demo aggregator */

/* ------------ Link map (from you) ------------ */
const LINK_MAP = {
  "TH39":"http://www.th34222.com/?r=bzu8899",
  "MB66":"http://www.mb661011.net/?r=gnv5085",
  "NEW88":"http://www.new882211.vip/?r=ioc2383",
  "78win":"http://www.78112277.com/?r=vzg7691",
  "789bet":"https://7893232.com/?r=N683RY",
  "F168":"https://www.f162288.cc/?id=262423264",
  "MK8":"https://www.mk81122.com/?af=X7T7JD",
  "PG68":"http://www.pg68833.xyz/?r=nko0130",
  "jun88":"https://www.jun8896.com/?af=PS47AC",
  "VG98":"http://www.vg981188.vip/?r=zuk5265",
  "777GAME":"http://yaoqing.77777vip9.com/?referralCode=jxd7503"
};

/* ------------ Data ------------ */
const ALL_GAMES = Object.keys(LINK_MAP);
const SOCIALS = [
  {name:'Telegram', url:'https://t.me/Pe_King0'},
  {name:'TikTok', url:'https://www.tiktok.com/@tgxpm_i5?_t=ZS-90sZSAevDj0&_r=1'},
  {name:'Twitter', url:'https://x.com/TGXPM_I5?s=09'},
  {name:'Instagram', url:'https://www.instagram.com/tgxpm_i5?igsh=bHF0YTIzeWdxczBp'},
  {name:'Facebook', url:'https://www.facebook.com/share/1ZRMKJqF7P/'},
  {name:'กลุ่ม 18+', url:'https://t.me/xxxgoii'}
];

/* ------------ UI refs ------------ */
const btnAnalyze = document.getElementById('btnAnalyze');
const btnSites = document.getElementById('btnSites');
const btnSocial = document.getElementById('btnSocial');
const overlay = document.getElementById('overlay');
const ovTitle = document.getElementById('ovTitle');
const ovGrid = document.getElementById('ovGrid');
const btnBack = document.getElementById('btnBack');

const scanOverlay = document.getElementById('scanOverlay');
const scanThumb = document.getElementById('scanThumb');
const scanName = document.getElementById('scanName');
const scanHint = document.getElementById('scanHint');
const scanPct = document.getElementById('scanPct');
const scanDetails = document.getElementById('scanDetails');
const openSiteBtn = document.getElementById('openSiteBtn');
const closeScanBtn = document.getElementById('closeScanBtn');
const visual = document.getElementById('visual');
const sweep = document.getElementById('sweep');

let currentPick = [];
let currentGameId = null;
let scanRunning = false;

/* ------------ Event binding ------------ */
btnSites.addEventListener('click', ()=> openList('games'));
btnSocial.addEventListener('click', ()=> openList('social'));
btnAnalyze.addEventListener('click', ()=> analyzePick());
btnBack.addEventListener('click', ()=> closeOverlay());
closeScanBtn.addEventListener('click', ()=> closeScan());
visual.addEventListener('click', ()=> startScan());

/* overlay open/close */
function openList(type){
  ovGrid.innerHTML = '';
  ovTitle.textContent = (type === 'games') ? 'รวมเว็บสล็อต' : 'ช่องทางโซเชียล';
  if(type === 'games'){
    ALL_GAMES.forEach(id => ovGrid.appendChild(makeCard(id, false)));
  } else {
    SOCIALS.forEach(s => ovGrid.appendChild(makeSocialCard(s)));
  }
  overlay.classList.add('show');
}
function closeOverlay(){ overlay.classList.remove('show'); }

/* make card for games */
function makeCard(id, isAnalyze, pct){
  const el = document.createElement('div');
  el.className = 'card';
  const img = `https://placehold.co/160x160/${randomColor()}/fff?text=${encodeURIComponent(id)}`;
  const percent = pct || random(70,99);
  el.innerHTML = `
    <img class="thumb" src="${img}" alt="${escapeHtml(id)}">
    <div class="meta"><div class="name">${escapeHtml(id)}</div><div class="desc">${isAnalyze ? 'ผลที่สุ่มมา (คลิกเพื่อสแกน)' : 'คลิกเพื่อไปที่เว็บ'}</div></div>
    <div style="display:flex;flex-direction:column;align-items:flex-end;gap:8px">
      <div class="badge">${percent}%</div>
      <div><button class="action">${isAnalyze ? 'เข้าเล่น' : 'ไปที่เว็บ'}</button></div>
    </div>`;
  const btn = el.querySelector('.action');
  if(isAnalyze){
    const wrapper = document.createElement('div');
    wrapper.className = 'glow-frame active';
    wrapper.appendChild(el);
    wrapper.addEventListener('click', ()=> openScannerFromPick(id, percent));
    btn.addEventListener('click', (e)=>{ e.stopPropagation(); openScannerFromPick(id, percent); });
    return wrapper;
  } else {
    btn.addEventListener('click', (e)=>{ e.stopPropagation(); goToLink(id); });
    el.addEventListener('click', ()=> goToLink(id));
    return el;
  }
}

/* social card maker */
function makeSocialCard(s){
  const el = document.createElement('div');
  el.className = 'card';
  const img = `https://placehold.co/120x120/222/fff?text=${encodeURIComponent(s.name)}`;
  el.innerHTML = `
    <img class="thumb" src="${img}" alt="${escapeHtml(s.name)}">
    <div class="meta"><div class="name">${escapeHtml(s.name)}</div><div class="desc">${escapeHtml(s.url)}</div></div>
    <div style="display:flex;flex-direction:column;align-items:flex-end;gap:8px">
      <div class="badge">LINK</div>
      <div><button class="action">เปิด</button></div>
    </div>`;
  const btn = el.querySelector('.action');
  btn.addEventListener('click', (e)=>{ e.stopPropagation(); window.open(s.url, '_self'); });
  el.addEventListener('click', ()=> window.open(s.url, '_self'));
  return el;
}

/* analyze pick: choose 3 unique random */
function analyzePick(){
  const pool = [...ALL_GAMES];
  const pick = [];
  while(pick.length < 3 && pool.length){
    const i = Math.floor(Math.random()*pool.length);
    pick.push(pool.splice(i,1)[0]);
  }
  currentPick = pick;
  renderAnalyze(pick);
}

/* render analyze results in overlay */
function renderAnalyze(pick){
  ovTitle.textContent = 'ผลวิเคราะห์ — สุ่ม 3 เว็บ';
  ovGrid.innerHTML = '';
  const top = document.createElement('div');
  top.style.display='flex'; top.style.justifyContent='space-between'; top.style.alignItems='center'; top.style.marginBottom='12px';
  top.innerHTML = `<div><button class="back" onclick="closeOverlay()">⬅️ กลับ</button></div>
  <div style="display:flex;gap:10px">
    <button class="back" onclick="analyzePick()">🔄 สแกนใหม่</button>
    <button class="back" onclick="closeOverlay()">ปิด</button>
  </div>`;
  ovGrid.appendChild(top);

  const wrap = document.createElement('div');
  wrap.className = 'analyze-wrap';
  pick.forEach(id=>{
    const pct = random(70,99);
    const cardWrap = makeCard(id, true, pct);
    wrap.appendChild(cardWrap);
  });
  ovGrid.appendChild(wrap);
  overlay.classList.add('show');
}

/* open scanner overlay for selected analyze card */
function openScannerFromPick(id, pct){
  currentGameId = id;
  scanThumb.src = `https://placehold.co/160x160/${randomColor()}/fff?text=${encodeURIComponent(id)}`;
  scanName.textContent = id;
  scanHint.textContent = 'แตะวงกลมเพื่อเริ่มสแกน';
  scanPct.textContent = '0%';
  scanDetails.innerHTML = '';
  openSiteBtn.onclick = ()=> openMappedLink(id);
  scanOverlay.classList.add('show');
  scanRunning = false;
}

/* start scan animation (user tap visual) */
function startScan(){
  if(scanRunning) return;
  scanRunning = true;
  scanHint.textContent = 'กำลังสแกน...';
  playScanSound();
  if(sweep){ sweep.style.transition = 'transform 2s linear'; sweep.style.transform = 'rotate(720deg)'; }
  const duration = random(1200,2400);
  const final = random(70,99);
  const start = performance.now();
  function step(now){
    const t = Math.min(1,(now-start)/duration);
    const eased = 1 - Math.pow(1-t,3);
    const cur = Math.floor(eased * final);
    scanPct.textContent = cur + '%';
    if(t < 1) requestAnimationFrame(step);
    else revealScan(final);
  }
  requestAnimationFrame(step);
}

/* reveal final scan and metrics */
function revealScan(percent){
  const metrics = [
    {k:'ยอดการเดิมพัน', v: clamp(percent + randRange(-6,6),10,99)},
    {k:'การจ่ายโบนัส', v: clamp(percent + randRange(-8,8),10,99)},
    {k:'อัตราชนะ-แพ้', v: clamp(percent + randRange(-5,5),10,99)},
    {k:'เวลาที่ดีที่สุด', v: clamp(random(10,95),5,99)}
  ];
  scanDetails.innerHTML = metrics.map(m => `
    <div class="row">
      <div class="label"><span>${m.k}</span><span class="font-bold">${m.v}%</span></div>
      <div class="bar"><div class="fill" style="width:${m.v}%"></div></div>
    </div>
  `).join('');
  scanHint.textContent = 'สแกนเสร็จแล้ว';
  openSiteBtn.onclick = ()=> openMappedLink(currentGameId);
  // update badges on page (best-effort)
  document.querySelectorAll('.badge').forEach(b=>{
    const parent = b.closest('.card') || b.closest('.glow-frame');
    if(!parent) return;
    const nameEl = parent.querySelector('.name');
    if(nameEl && nameEl.textContent.trim() === currentGameId) b.textContent = percent + '%';
  });
}

/* open mapped link (same tab) */
function openMappedLink(id){
  const url = LINK_MAP[id] || '#';
  if(!url || url === '#'){ alert('ลิงก์ไม่พร้อมใช้งาน'); return; }
  window.location.href = url;
}

/* close scan overlay */
function closeScan(){ scanOverlay.classList.remove('show'); scanRunning=false; currentGameId=null }

/* helpers */
function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') }
function random(min,max){ return Math.floor(Math.random()*(max-min+1))+min }
function randRange(a,b){ return Math.floor(Math.random()*(b-a+1))+a }
function clamp(v,a,b){ return Math.max(a,Math.min(b,Math.round(v))) }
function randomColor(){ const colors=['6A5ACD','8B5CF6','7c3aed','f59e0b','059669','ef4444','60A5FA','F97316','374151','b34bff'];return colors[Math.floor(Math.random()*colors.length)];}

/* small scan sound */
let ac;
function playScanSound(){
  try{
    if(!ac) ac = new (window.AudioContext || window.webkitAudioContext)();
    const o = ac.createOscillator(); const g = ac.createGain();
    o.type='sine'; o.frequency.value=880; g.gain.value=0.0001;
    o.connect(g); g.connect(ac.destination); o.start();
    g.gain.exponentialRampToValueAtTime(0.06, ac.currentTime + 0.02);
    setTimeout(()=>{ g.gain.exponentialRampToValueAtTime(0.0001, ac.currentTime + 0.16); o.stop(ac.currentTime + 0.17); }, 160);
  }catch(e){ /* may be blocked by autoplay */ }
}

/* ESC to close */
document.addEventListener('keydown', e=> { if(e.key==='Escape'){ closeOverlay(); closeScan(); }});
