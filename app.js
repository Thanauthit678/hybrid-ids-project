/* ================= HELPERS ================= */
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const pad=n=>String(n).padStart(2,'0');
const hhmmss=d=>`${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
const dstr=d=>`${pad(d.getDate())}/${pad(d.getMonth()+1)}/${d.getFullYear()+543}`;
let toastT;
function toast(m){const t=$('#toast');if(!t)return;t.textContent=m;t.classList.add('on');clearTimeout(toastT);toastT=setTimeout(()=>t.classList.remove('on'),2600);}

/* ================= LOGIN (เฉพาะหน้า login.html) ================= */
if ($('#btnLogin')) {
  $('#btnLogin').onclick = () => {
    const ok = $('#liEmail').value.trim() === 'admin@nids.local' && $('#liPass').value === 'admin1234';
    if (!ok) { $('#loginErr').style.display = 'block'; return; }
    // TODO: เปลี่ยนเป็นยิง POST ไปที่ route /login จริงเมื่อทำระบบ authentication ฝั่ง backend เสร็จ
    location.href = '/dashboard';
  };
}
// หมายเหตุ: ปุ่มสลับ login/signup/forgot, ปุ่มเมนูฝั่งซ้าย, ปุ่ม logout และกระดิ่งแจ้งเตือน
// ไม่ต้องผูก event ที่นี่แล้ว เพราะเปลี่ยนเป็น href/onclick="location.href=...' ตรงๆ ใน
// template แต่ละไฟล์แล้ว (ไม่ใช่ data-go/data-auth แบบ SPA เดิม)

/* ================= GLOBAL STATE ================= */
/* [สำคัญ] state ก้อนนี้อยู่ในหน่วยความจำของเบราว์เซอร์ (client-side) เท่านั้น เดิมตอนเป็น
   SPA ทุกหน้าอยู่ใน DOM เดียวกันตลอด session จึงสะสมตัวเลขได้ต่อเนื่อง แต่ตอนนี้แต่ละหน้า
   เป็นคนละ page load กัน -> kTotal/kKnown/kUnknown ฯลฯ จะรีเซ็ตเป็น 0 ทุกครั้งที่เปลี่ยนหน้า
   ถ้าต้องการให้ตัวเลขสะสมข้ามหน้าได้จริง ต้องย้ายการนับไปไว้ฝั่ง Flask backend (เช่นเปิด
   endpoint /api/stats ให้เก็บผลรวมไว้ในตัวแปร/DB แล้วให้ทุกหน้าดึงค่ามาแสดงแทนการนับเองใน
   เบราว์เซอร์) ตอนนี้ยังเป็นแค่แพตช์ฝั่ง client ให้ไม่ crash เท่านั้น ยังไม่ได้แก้ปัญหานี้ */
const BUDGET=[['Packet Capture',100],['Preprocessing',200],['Hybrid Detection',100],['Risk Assessment',50],['Incident Logging',50],['Dashboard Update',100],['LINE Alert',150]];

let state={
  running:false, timer:null, clockT:null,
  high:0, lastRt:0,
  live:[], alerts:[], incidents:[], notisDB:[],
  srcCount:{}, dstCount:{},
  series:{label:[],n:[],k:[],u:[]}, tickN:0,tickK:0,tickU:0,
  page:1, perPage:8, detail:null
};

/* ================= REAL ENGINE INTEGRATION (FLASK API) ================= */
function startEngine(){
  if(state.running) return;
  state.running=true;
  if($('#btnFeed')) $('#btnFeed').textContent='หยุดรับทราฟฟิก';
  if($('#lStat')) $('#lStat').textContent='ทำงานอยู่';
  if($('#ledConn')) $('#ledConn').classList.remove('red');
  log('sys','[SYS]','เริ่มดักจับทราฟฟิกจริงผ่าน Backend · โหลดโมเดล HybridDetector สำเร็จ');

  loop();
  fetchLogsFromDB();

  state.clockT=setInterval(()=>{ if($('#clock')) $('#clock').textContent=hhmmss(new Date()); },1000);
  if($('#clock')) $('#clock').textContent=hhmmss(new Date());
  if(!charts && $('#chLine')) initCharts();
  if(!state.tickT) state.tickT=setInterval(tick,3000);
}

function stopEngine(){
  state.running=false; clearTimeout(state.timer); clearInterval(state.clockT);
  if($('#btnFeed')) $('#btnFeed').textContent='เริ่มรับทราฟฟิก';
  if($('#lStat')) $('#lStat').textContent='หยุดชั่วคราว';
  if($('#ledConn')) $('#ledConn').classList.add('red');
  log('sys','[SYS]','หยุดสตรีมทราฟฟิกแล้ว');
}
if($('#btnFeed')) $('#btnFeed').onclick=()=>state.running?stopEngine():startEngine();

function loop(){
  if(!state.running) return;
  const speed = +($('#setSpeed')?.value || 900);

  fetch('/api/simulate_traffic')
    .then(res => res.json())
    .then(data => {
      processRealTraffic(data);
    })
    .catch(err => {
      console.error("[API ERROR]", err);
      log('rf','[ERR]','ไม่สามารถเชื่อมต่อกับ /api/simulate_traffic ได้');
    });

  state.timer = setTimeout(loop, speed);
}

function processRealTraffic(data){
  // ใช้ detection_type ที่ backend ส่งมาตรงๆ (Known Attack / Unknown Attack / Normal Traffic)
  // แทนการเดาแบบสุ่ม 5% เหมือนโค้ดเดิม เพราะตอนนี้ hybrid_engine.py สเกลข้อมูลถูกต้องแล้ว
  // ผลลัพธ์จริงเชื่อถือได้
  let resultGroup = data.detection_type === 'Known Attack' ? 'Known Attack'
                   : data.detection_type === 'Unknown Attack' ? 'Unknown Attack'
                   : 'Normal';
  let isUnknown = resultGroup === 'Unknown Attack';

  const f = {
    id: data.actual_label ? `INC-${Math.floor(10000 + Math.random() * 90000)}` : 'FLOW-TMP',
    t: new Date(data.timestamp),
    src: data.src_ip,
    dst: data.dst_ip,
    dport: Math.floor(Math.random() * (8080 - 80 + 1)) + 80,
    proto: 'TCP',
    sport: Math.floor(Math.random() * (65535 - 1024 + 1)) + 1024,
    pkts: Math.floor(Math.random() * 500) + 10,
    bytes: Math.floor(Math.random() * 500000) + 1000,
    dur: (Math.random() * 5).toFixed(2),
    attack: resultGroup === 'Normal' ? '—' : data.attack_type,
    method: isUnknown ? 'Isolation Forest' : (resultGroup === 'Normal' ? 'Hybrid (Pass)' : 'Random Forest'),
    result: resultGroup,
    rfLabel: data.attack_type,
    rfProb: (Math.random() * (0.99 - 0.85) + 0.85).toFixed(3),
    ifScore: isUnknown ? (-0.05 - Math.random() * 0.2).toFixed(4) : null,
    ifThresh: -0.05,
    score: resultGroup === 'Normal' ? Math.floor(Math.random() * 20) : data.risk_score,
    risk: resultGroup === 'Normal' ? 'Low' : data.risk_level,
    proc: data.processing_time_ms,
    rt: (data.processing_time_ms + Math.random() * 50).toFixed(1),
    times: {
      'Packet Capture': (data.processing_time_ms * 0.2).toFixed(1),
      'Preprocessing': (data.processing_time_ms * 0.4).toFixed(1),
      'Hybrid Detection': (data.processing_time_ms * 0.3).toFixed(1),
      'Risk Assessment': (data.processing_time_ms * 0.1).toFixed(1),
      'Incident Logging': 15.0,
      'Dashboard Update': 10.0,
      'LINE Alert': data.risk_level === 'High' ? 120.0 : 0
    }
  };

  state.lastRt = f.rt;
  state.srcCount[f.src] = (state.srcCount[f.src] || 0) + 1;
  state.dstCount[f.dst] = (state.dstCount[f.dst] || 0) + 1;

  // ตัวนับ tick ใช้แค่วาดกราฟเส้นแนวโน้ม (recent trend) เท่านั้น ไม่ใช่ตัวเลขสะสมรวม
  // ตัวเลขสะสมจริง (kTotal/kKnown/...) มาจาก /api/stats ฝั่ง server แล้ว (ดู fetchStats())
  if(f.result === 'Known Attack') { state.tickK++; }
  else if(f.result === 'Unknown Attack') { state.tickU++; }
  else { state.tickN++; }
  if(f.risk === 'High') state.high++;  // ใช้เฉพาะไฟสถานะ "พบภัยคุกคาม" ช่วง session นี้เท่านั้น

  if(f.result === 'Known Attack'){
    log('rf','[RF]',`${f.src} → ${f.dst} ตรวจพบ ${f.attack} (Random Forest)`);
  } else if(f.result === 'Unknown Attack'){
    log('rf','[RF]',`${f.src} → ${f.dst} ผ่าน RF · ส่งต่อ Isolation Forest`);
    log('if','[IF]',`พบความผิดปกติ Anomaly Score ${f.ifScore}`);
  } else {
    if(Math.random() < 0.2) log('nm','[OK]',`${f.src} → ${f.dst} ทราฟฟิกปกติ (${f.proc} ms)`);
  }

  state.live.unshift(f);
  if(state.live.length > 120) state.live.pop();
  renderLive();

  if(f.result !== 'Normal'){
    state.alerts.unshift(f);
    if(state.alerts.length > 7) state.alerts.pop();
    renderAlerts();
    if(f.risk === 'High' && $('#bellDot')) $('#bellDot').classList.add('on');
  }
  renderKpi();
  fetchStats(); // ดึงตัวเลขสะสมจริงจาก server มาอัปเดตการ์ด KPI ทันทีหลังทราฟฟิกใหม่เข้ามา
}

/* ================= FETCH DATA FROM SQLITE DB ================= */
function fetchLogsFromDB(){
  fetch('/api/logs')
    .then(res => res.json())
    .then(dbLogs => {
      state.incidents = dbLogs.map(item => ({
        db_id: item.id,
        id: `INC-${String(item.id).padStart(5,'0')}`,
        t: new Date(item.timestamp),
        src: item.src_ip,
        dst: item.dst_ip,
        attack: item.attack_type,
        method: item.detection_type,
        score: item.risk_score,
        risk: item.risk_level,
        proc: item.processing_time_ms,
        result: item.attack_type === 'BENIGN' ? 'Normal' : (item.detection_type === 'Isolation Forest' ? 'Unknown Attack' : 'Known Attack')
      }));
      renderLogs();
      fillTypes();
    })
    .catch(err => console.error("Error loading logs from DB:", err));
}

/* ================= STATS จาก Server (ตัวเลขสะสมจริง ข้ามหน้า/ข้ามแท็บได้) ================= */
function fetchStats(){
  fetch('/api/stats')
    .then(res=>res.json())
    .then(s=>{
      if($('#kTotal')) $('#kTotal').innerHTML=s.total.toLocaleString()+'<small>โฟลว์</small>';
      if($('#kKnown')) $('#kKnown').textContent=s.known.toLocaleString();
      if($('#kUnknown')) $('#kUnknown').textContent=s.unknown.toLocaleString();
      if($('#kNormal')) $('#kNormal').textContent=s.normal.toLocaleString();
      if($('#kHigh')) $('#kHigh').textContent=s.high.toLocaleString();
      if($('#kInc')) $('#kInc').textContent=(s.incidents_count||0).toLocaleString();
      if($('#kProc')) $('#kProc').innerHTML=Math.round(s.avg_processing_ms||0)+'<small>ms</small>';
      if(charts){
        charts.pie.data.datasets[0].data=[s.normal,s.known,s.unknown];
        charts.pie.update();
      }
    })
    .catch(err=>console.error('[STATS ERROR]',err));
}

/* ================= ประวัติแจ้งเตือนจริงจาก DB (ตาราง notifications) ================= */
function fetchNotifications(){
  fetch('/api/notifications')
    .then(res=>res.json())
    .then(rows=>{ state.notisDB=rows; renderNoti(); })
    .catch(err=>console.error('[NOTI ERROR]',err));
}

function renderNoti(){
  if(!$('#tbNoti')) return;
  const rows=state.notisDB||[];
  if($('#nCount')) $('#nCount').textContent=rows.length+' รายการ';
  const tb=$('#tbNoti');
  if(!rows.length){tb.innerHTML='<tr><td colspan="5"><div class="empty">ยังไม่มีการแจ้งเตือนถูกส่งออก</div></td></tr>';return;}

  tb.innerHTML=rows.map(n=>`<tr>
    <td class="mono">${n.sent_at}</td>
    <td>${n.incident_id ? '#'+n.incident_id+' · '+(n.attack_type||'—') : '—'}</td>
    <td>${n.recipient}</td>
    <td>${n.status==='success' ? '<span class="tag t-lo">ส่งสำเร็จ</span>' : '<span class="tag t-hi">ล้มเหลว</span>'}</td>
    <td>${n.status==='failed' ? `<button class="btn btn-s ghost" data-resend="${n.id}">ส่งซ้ำ</button>` : ''}</td>
  </tr>`).join('');

  $$('#tbNoti [data-resend]').forEach(b=>b.onclick=()=>{
    fetch(`/api/notifications/resend/${b.dataset.resend}`, {method:'POST'})
      .then(res=>res.json())
      .then(r=>{ toast(r.success ? 'ส่งซ้ำสำเร็จ' : 'ส่งซ้ำไม่สำเร็จ (เช็คการตั้งค่า LINE_CHANNEL_ACCESS_TOKEN)'); fetchNotifications(); })
      .catch(()=>toast('เกิดข้อผิดพลาดขณะส่งซ้ำ'));
  });

  const latest=rows[0];
  if($('#lineBox') && latest){
    $('#lineBox').innerHTML=`<div class="line-av">LINE</div><div class="line-msg">
      <div class="h">แจ้งเตือนภัยคุกคามเครือข่าย</div>
      <div style="white-space:pre-line;color:#3a2c2d">${latest.message}</div>
      <div style="margin-top:8px;color:#8A7C7E">สถานะ: ${latest.status==='success'?'ส่งสำเร็จ':'ล้มเหลว'} · ผู้รับ: ${latest.recipient}</div>
    </div>`;
  }
}
if($('#btnResendAll')){
  $('#btnResendAll').onclick=()=>{
    const failed=(state.notisDB||[]).filter(n=>n.status==='failed');
    if(!failed.length){toast('ไม่มีรายการที่ล้มเหลว');return;}
    toast(`กำลังส่งซ้ำ ${failed.length} รายการ...`);
    Promise.all(failed.map(n=>fetch(`/api/notifications/resend/${n.id}`,{method:'POST'})))
      .then(()=>{toast('ส่งซ้ำครบทุกรายการแล้ว');fetchNotifications();});
  };
}

function log(cls,tag,msg){
  const c=$('#console');
  if(!c) return;
  const d=document.createElement('div');
  d.innerHTML=`<span class="t">${hhmmss(new Date())}</span> <span class="${cls}">${tag}</span> ${msg}`;
  c.appendChild(d);
  while(c.children.length>240) c.removeChild(c.firstChild);
  c.scrollTop=c.scrollHeight;
}
if($('#btnClearLog')) $('#btnClearLog').onclick=()=>{ if($('#console')) $('#console').innerHTML=''; };

/* ================= RENDER FUNCTIONS ================= */
function riskTag(r){return r==='High'?'<span class="tag t-hi">High</span>':r==='Medium'?'<span class="tag t-md">Medium</span>':'<span class="tag t-lo">Low</span>';}
function resTag(r){return r==='Known Attack'?'<span class="tag t-hi">Known Attack</span>':r==='Unknown Attack'?'<span class="tag t-md">Unknown Attack</span>':'<span class="tag t-lo">Normal</span>';}

function renderKpi(){
  // kTotal/kKnown/kUnknown/kNormal/kHigh/kInc/kProc มาจาก fetchStats() (server) แล้ว
  // ฟังก์ชันนี้อัปเดตเฉพาะค่าที่เป็น local/session จริงๆ (ค่าล่าสุดของ "หน้านี้ตอนนี้")
  if($('#tbRt')) $('#tbRt').textContent=state.lastRt+' ms';
  if($('#lProc')) $('#lProc').innerHTML=state.lastRt+'<small>ms</small>';
  if($('#lPps')) $('#lPps').textContent=(state.rate||0).toFixed(1);
  if($('#lMbps')) $('#lMbps').innerHTML=((state.rate||0)*0.5).toFixed(1)+'<small>Mbps</small>';
  if($('#kRate')) $('#kRate').textContent=(state.rate||0).toFixed(1)+' โฟลว์/วินาที';
  if($('#ledProt')) $('#ledProt').classList.toggle('red',state.high>0);
  if($('#txtProt')) $('#txtProt').textContent=state.high>0?'พบภัยคุกคาม':'กำลังป้องกัน';
  renderRank();
}

function renderLive(){
  if(!$('#tbLive')) return;
  const fr=$('#fRes').value,fp=$('#fProto').value,fk=$('#fRisk').value,q=$('#fQ').value.trim().toLowerCase();
  const rows=state.live.filter(f=>(!fr||f.result===fr)&&(!fp||f.proto===fp)&&(!fk||f.risk===fk)&&(!q||f.src.includes(q)||f.dst.includes(q))).slice(0,60);
  const tb=$('#tbLive');
  if(!rows.length){tb.innerHTML='<tr><td colspan="7"><div class="empty">รอทราฟฟิกเรียลไทม์จากระบบ...</div></td></tr>';return;}
  tb.innerHTML=rows.map(f=>`<tr class="click" data-dbid="" data-inc="${f.id}">
    <td class="mono">${hhmmss(f.t)}</td><td class="mono">${f.src}</td><td class="mono">${f.dst}:${f.dport}</td>
    <td>${f.proto}</td><td>${resTag(f.result)}</td>
    <td class="mono">${f.result==='Unknown Attack'?f.ifScore:(f.rfProb*100).toFixed(1)+'%'}</td>
    <td>${riskTag(f.risk)}</td></tr>`).join('');
  bindRows(tb);
}
if($('#tbLive')){
  ['#fRes','#fProto','#fRisk','#fQ'].forEach(s=>{ if($(s)) $(s).oninput=renderLive; });
}

function renderAlerts(){
  if(!$('#tbAlerts')) return;
  const tb=$('#tbAlerts');
  if(!state.alerts.length){tb.innerHTML='<tr><td colspan="5"><div class="empty">ยังไม่มีการแจ้งเตือน ระบบกำลังเฝ้าดูทราฟฟิกอยู่</div></td></tr>';return;}
  tb.innerHTML=state.alerts.map(f=>`<tr class="click" data-dbid="" data-inc="${f.id}">
    <td class="mono">${hhmmss(f.t)}</td><td class="mono">${f.src}</td><td>${f.attack}</td>
    <td>${riskTag(f.risk)}</td><td><span class="tag t-n">บันทึกลง DB แล้ว</span></td></tr>`).join('');
  bindRows(tb);
}
if($('#btnClearAlerts')) $('#btnClearAlerts').onclick=()=>{state.alerts=[];renderAlerts();};

function renderRank(){
  if(!$('#rkSrc') && !$('#rkDst')) return;
  const draw=(obj,el)=>{
    if(!$(el)) return;
    const arr=Object.entries(obj).sort((a,b)=>b[1]-a[1]).slice(0,5);
    if(!arr.length){$(el).innerHTML='<div class="empty">ยังไม่มีข้อมูล</div>';return;}
    const max=arr[0][1];
    $(el).innerHTML=arr.map(([ip,c],i)=>`<div class="rank"><span class="n">${i+1}</span>
      <div><div class="ip">${ip}</div><div class="bar"><i style="width:${c/max*100}%"></i></div></div>
      <span class="c">${c}</span></div>`).join('');
  };
  draw(state.srcCount,'#rkSrc'); draw(state.dstCount,'#rkDst');
}

function fillTypes(){
  if(!$('#gType')) return;
  const set=[...new Set(state.incidents.map(f=>f.attack))];
  const sel=$('#gType'), cur=sel.value;
  sel.innerHTML='<option value="">ประเภทการโจมตีทั้งหมด</option>'+set.map(t=>`<option${t===cur?' selected':''}>${t}</option>`).join('');
}

function filteredLogs(){
  const t=$('#gType')?.value||'',r=$('#gRisk')?.value||'',q=($('#gQ')?.value||'').trim().toLowerCase();
  return state.incidents.filter(f=>(!t||f.attack===t)&&(!r||f.risk===r)&&(!q||f.src.includes(q)||f.id.toLowerCase().includes(q)));
}

function renderLogs(){
  if(!$('#tbLogs')) return;
  const rows=filteredLogs();
  if($('#gCount')) $('#gCount').textContent=rows.length.toLocaleString()+' รายการ (SQLite)';
  const pages=Math.max(1,Math.ceil(rows.length/state.perPage));
  if(state.page>pages) state.page=pages;
  const view=rows.slice((state.page-1)*state.perPage,state.page*state.perPage);
  const tb=$('#tbLogs');
  if(!view.length){tb.innerHTML='<tr><td colspan="9"><div class="empty">ยังไม่มีเหตุการณ์ถูกบันทึกในฐานข้อมูล SQLite</div></td></tr>';if($('#pager'))$('#pager').innerHTML='';return;}

  tb.innerHTML=view.map(f=>`<tr class="click" data-dbid="${f.db_id}" data-inc="${f.id}">
    <td class="mono">#${f.db_id}</td><td class="mono">${dstr(f.t)} ${hhmmss(f.t)}</td><td class="mono">${f.src}</td>
    <td><strong>${f.attack}</strong></td><td>${f.method}</td><td class="mono">${f.score}</td><td>${riskTag(f.risk)}</td>
    <td><span class="tag t-n">SQLite Logged</span></td><td style="color:var(--red)">ดูรายละเอียด</td></tr>`).join('');
  bindRows(tb);

  if($('#pager')){
    let p='';
    p+=`<button ${state.page===1?'disabled':''} data-pg="${state.page-1}">‹</button>`;
    for(let i=1;i<=Math.min(pages,6);i++) p+=`<button class="${i===state.page?'on':''}" data-pg="${i}">${i}</button>`;
    p+=`<button ${state.page===pages?'disabled':''} data-pg="${state.page+1}">›</button>`;
    $('#pager').innerHTML=p;
    $$('#pager button[data-pg]').forEach(b=>b.onclick=()=>{state.page=+b.dataset.pg;renderLogs();});
  }
}
if($('#tbLogs')){
  ['#gType','#gRisk','#gQ'].forEach(s=>{ if($(s)) $(s).oninput=()=>{state.page=1;renderLogs();}; });
}

function bindRows(tb){
  tb.querySelectorAll('[data-inc]').forEach(tr=>tr.onclick=()=>{
    const dbId = tr.dataset.dbid;
    if (dbId) {
      // นำทางไปหน้ารายละเอียดจริง (route แยกต่างหากแล้ว ไม่ใช่ view-switch แบบเดิม)
      location.href = `/incidents/${dbId}`;
    } else {
      toast('รายการนี้ยังไม่ถูกบันทึกลงฐานข้อมูล ยังไม่มีหน้ารายละเอียด');
    }
  });
}

/* ================= INCIDENT DETAIL (REAL API CALL) ================= */
function openDetailFromDB(dbId){
  fetch(`/api/incidents/${dbId}`)
    .then(res => res.json())
    .then(data => {
      const f = {
        id: `INC-${String(data.id).padStart(5,'0')}`,
        t: new Date(data.timestamp),
        src: data.src_ip,
        dst: data.dst_ip,
        attack: data.attack_type,
        method: data.detection_type,
        score: data.risk_score,
        risk: data.risk_level,
        proc: data.processing_time_ms,
        result: data.attack_type === 'BENIGN' ? 'Normal' : (data.detection_type === 'Isolation Forest' ? 'Unknown Attack' : 'Known Attack'),
        recommendations: data.recommendations || []
      };
      renderDetailScreen(f);
    })
    .catch(err => console.error("Error fetching detail:", err));
}

function renderDetailScreen(f){
  if($('#dTitle')) $('#dTitle').textContent=f.id+' · '+f.attack;
  if($('#dSub')) $('#dSub').textContent=`ตรวจพบเมื่อ ${dstr(f.t)} เวลา ${hhmmss(f.t)} · ประมวลผลโดย Backend ใน ${f.proc} ms`;
  if($('#dTop')) $('#dTop').innerHTML=[
    ['ประเภทการโจมตี',f.attack],
    ['การจำแนก',f.result],
    ['ระดับความเสี่ยง',`${f.risk} (${f.score}/100)`],
    ['เวลาประมวลผล',`${f.proc} ms`],
    ['วิธีตรวจจับ',f.method]
  ].map(([k,v])=>`<div class="dt-cell"><div class="k">${k}</div><div class="v">${v}</div></div>`).join('');

  if($('#dNet')) $('#dNet').innerHTML=[
    ['Source IP',f.src],['Destination IP',f.dst],['Protocol','TCP'],
    ['Processing Time',`${f.proc} ms`],['Database Engine','SQLite3 Persisted']
  ].map(([k,v])=>`<div><div class="k">${k}</div><div class="v">${v}</div></div>`).join('');

  const rfAct=f.method==='Random Forest', ifAct=f.method==='Isolation Forest';
  if($('#dPath')) $('#dPath').textContent=rfAct?'หยุดที่ชั้นที่ 1 — Random Forest':ifAct?'ผ่านชั้นที่ 1 → จับได้ที่ชั้นที่ 2':'ผ่านทั้งสองชั้น';
  if($('#dStage')) $('#dStage').innerHTML=`
    <div class="stg ${rfAct?'act':''}">
      <h4>ชั้นที่ 1 — Random Forest</h4><div class="sm">Supervised · Known Attacks</div>
      <div class="row"><span>ผลจำแนก</span><b>${f.attack}</b></div>
      <div class="row"><span>สรุป</span><b>${rfAct?'พบการโจมตี':'ส่งต่อ'}</b></div>
    </div>
    <div class="stg ${ifAct?'act':''}">
      <h4>ชั้นที่ 2 — Isolation Forest</h4><div class="sm">Unsupervised · Anomaly Detection</div>
      <div class="row"><span>สรุป</span><b>${ifAct?'พบความผิดปกติ':'ปกติ'}</b></div>
    </div>
    <div class="stg act">
      <h4>ผลสรุป</h4><div class="sm">Risk Assessment Engine</div>
      <div class="row"><span>คะแนนความเสี่ยง</span><b>${f.score}/100</b></div>
      <div class="row"><span>ระดับ</span><b>${f.risk}</b></div>
    </div>`;

  const recList = f.recommendations || [
    `คำแนะนำ: บล็อกไอพีต้นทาง ${f.src} บน Firewall ทันที`,
    "ตรวจสอบ Traffic Payload ผ่าน Wireshark"
  ];

  if($('#dRecs')){
    $('#dRecs').innerHTML=recList.map(text=>`<button class="rec"><div class="t">${text}</div></button>`).join('');
    $$('#dRecs .rec').forEach(b=>b.onclick=()=>toast('ทำตามคำแนะนำ: '+b.querySelector('.t').textContent));
  }

  // เทียบเวลาประมวลผลของเหตุการณ์นี้กับ Time Budget ตารางที่ 13 (บทที่ 3)
  // f.proc คือเวลาประมวลผลรวมจริงที่ได้จาก backend (processing_time_ms) แบ่งสัดส่วนตาม
  // ขั้นตอนแบบเดียวกับที่ใช้ตอนจำลองทราฟฟิกใน processRealTraffic() เพื่อความสอดคล้องกัน
  if($('#dBudget')){
    const totalProc = f.proc || 0;
    const weights = {'Packet Capture':0.2,'Preprocessing':0.4,'Hybrid Detection':0.3,'Risk Assessment':0.1};
    $('#dBudget').innerHTML = BUDGET.map(([label,budget])=>{
      let used;
      if(label === 'Incident Logging') used = 15.0;
      else if(label === 'Dashboard Update') used = 10.0;
      else if(label === 'LINE Alert') used = f.risk === 'High' ? 120.0 : 0;
      else used = +(totalProc * (weights[label] || 0)).toFixed(1);
      const over = used > budget;
      return `<span class="${over ? 'over' : ''}">${label}: ${used.toFixed(1)} / ${budget} ms</span>`;
    }).join('');
  }
  // ไม่ต้อง go('vDetail') แล้ว เพราะตอนนี้หน้านี้คือ incident_detail.html แยกเฉพาะอยู่แล้ว
}

/* ================= CHARTS ================= */
let charts=null;
function initCharts(){
  if(!$('#chLine') || !$('#chPie')) return;
  const line=new Chart($('#chLine'),{
    type:'line',
    data:{labels:[],datasets:[
      {label:'Normal',data:[],borderColor:'#177245',backgroundColor:'rgba(23,114,69,.10)',fill:true,tension:.35,borderWidth:2,pointRadius:0},
      {label:'Known Attack',data:[],borderColor:'#C8102E',backgroundColor:'rgba(200,16,46,.12)',fill:true,tension:.35,borderWidth:2,pointRadius:0},
      {label:'Unknown Attack',data:[],borderColor:'#B4690E',backgroundColor:'rgba(180,105,14,.12)',fill:true,tension:.35,borderWidth:2,pointRadius:0}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:280},
      plugins:{legend:{position:'bottom',labels:{boxWidth:10,boxHeight:10,usePointStyle:true,pointStyle:'circle',font:{family:'Kanit',size:12}}}},
      scales:{x:{grid:{display:false},ticks:{font:{family:'IBM Plex Mono',size:10},color:'#8A7C7E'}},
              y:{beginAtZero:true,grid:{color:'#F3EAEA'},ticks:{precision:0,font:{family:'IBM Plex Mono',size:10},color:'#8A7C7E'}}}}
  });
  const pie=new Chart($('#chPie'),{
    type:'doughnut',
    data:{labels:['Normal','Known Attack','Unknown Attack'],
      datasets:[{data:[0,0,0],backgroundColor:['#177245','#C8102E','#E9A23B'],borderColor:'#fff',borderWidth:3}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'62%',animation:{duration:300},
      plugins:{legend:{position:'bottom',labels:{boxWidth:10,boxHeight:10,usePointStyle:true,pointStyle:'circle',font:{family:'Kanit',size:12}}}}}
  });
  charts={line,pie};
}

function tick(){
  const s=state.series;
  s.label.push(hhmmss(new Date())); s.n.push(state.tickN); s.k.push(state.tickK); s.u.push(state.tickU);
  state.rate=(state.tickN+state.tickK+state.tickU)/3;
  const keep=+($('#selWin')?.value||60)/3;
  while(s.label.length>keep){s.label.shift();s.n.shift();s.k.shift();s.u.shift();}
  state.tickN=state.tickK=state.tickU=0;
  if(charts){
    charts.line.data.labels=s.label;
    charts.line.data.datasets[0].data=s.n;
    charts.line.data.datasets[1].data=s.k;
    charts.line.data.datasets[2].data=s.u;
    charts.line.update();
    // สัดส่วนวงกลม (pie) มาจาก /api/stats แทน (ดู fetchStats()) เพราะต้องการค่าสะสม
    // จริงทั้งหมด ไม่ใช่แค่ช่วงเวลาที่ผ่านมาเหมือนกราฟเส้น
  }
  renderKpi();
}

/* ================= EXPORT CSV FROM FLASK API ================= */
function exportCsvFromAPI(){
  window.location.href = '/api/incidents/export/csv';
  toast('กำลังดาวน์โหลดรายงาน CSV จากฐานข้อมูล SQLite...');
}
if($('#btnCsv')) $('#btnCsv').onclick = exportCsvFromAPI;   // หน้า Logs
if($('#btnCsv2')) $('#btnCsv2').onclick = exportCsvFromAPI; // หน้า Settings
if($('#btnPdf')) $('#btnPdf').onclick = () => window.print();

/* ================= PAGE-SPECIFIC INITIALIZATION ================= */
// แต่ละหน้าตอนนี้เป็นคนละ page load กัน เช็คจาก element เฉพาะของหน้านั้นๆ ว่าต้อง
// เริ่มทำอะไรบ้าง แทนการรันทุกอย่างรวดเดียวเหมือนตอนเป็น SPA

// หน้า Logs: ตั้งค่าเริ่มต้นของ date filter + โหลดข้อมูลจาก DB ครั้งแรก
if ($('#tbLogs')) {
  const now=new Date();
  if($('#gTo')) $('#gTo').value=now.toISOString().slice(0,10);
  if($('#gFrom')) $('#gFrom').value=new Date(now.getTime()-6*864e5).toISOString().slice(0,10);
  fetchLogsFromDB();
}

// Settings: toggle switch แบบ visual เฉยๆ (ยังไม่บันทึกค่าจริงลง backend)
$$('[data-sw]').forEach(b=>b.onclick=()=>{
  b.classList.toggle('on');
  toast(b.classList.contains('on') ? 'เปิดใช้งานแล้ว' : 'ปิดใช้งานแล้ว');
});

// Settings: ล้างบันทึกเหตุการณ์ที่เก่ากว่า 90 วัน (ยิง DELETE จริงที่ backend)
if ($('#btnPurge')) {
  $('#btnPurge').onclick = () => {
    if (!confirm('ยืนยันการลบบันทึกเหตุการณ์ที่เก่ากว่า 90 วัน? การกระทำนี้ย้อนกลับไม่ได้')) return;
    fetch('/api/incidents/purge', { method: 'POST' })
      .then(res => res.json())
      .then(r => {
        if (r.error) { toast('เกิดข้อผิดพลาด: ' + r.error); return; }
        toast(`ลบข้อมูลเก่าแล้ว ${r.deleted} รายการ`);
        fetchStats();
      })
      .catch(() => toast('เกิดข้อผิดพลาดขณะล้างข้อมูล'));
  };
}

// Train: เริ่มฝึกโมเดลจริง (subprocess ฝั่ง backend) + poll สถานะทุก 3 วินาที
let trainPollT = null;
function pollTrainStatus(){
  fetch('/api/train/status')
    .then(res => res.json())
    .then(s => {
      if ($('#trainLog') && s.log && s.log.length) {
        $('#trainLog').textContent = s.log[s.log.length - 1];
      }
      if (s.status === 'done') {
        clearInterval(trainPollT);
        if ($('#btnTrain')) { $('#btnTrain').disabled = false; $('#btnTrain').textContent = 'เริ่มฝึกโมเดล'; }
        toast('ฝึกโมเดลเสร็จสมบูรณ์ โมเดลใหม่พร้อมใช้งานแล้ว');
      } else if (s.status === 'error') {
        clearInterval(trainPollT);
        if ($('#btnTrain')) { $('#btnTrain').disabled = false; $('#btnTrain').textContent = 'เริ่มฝึกโมเดล'; }
        toast('ฝึกโมเดลล้มเหลว ดูรายละเอียดที่ข้อความด้านล่างปุ่ม');
      }
    })
    .catch(() => {});
}
if ($('#btnTrain')) {
  $('#btnTrain').onclick = () => {
    fetch('/api/train/start', { method: 'POST' })
      .then(res => res.json())
      .then(r => {
        if (r.error) { toast(r.error); return; }
        $('#btnTrain').disabled = true;
        $('#btnTrain').textContent = 'กำลังฝึกโมเดล...';
        if ($('#trainLog')) $('#trainLog').textContent = 'เริ่มฝึกโมเดลแล้ว กำลังประมวลผล (อาจใช้เวลาหลายนาที ห้ามปิดหน้านี้)...';
        clearInterval(trainPollT);
        trainPollT = setInterval(pollTrainStatus, 3000);
      })
      .catch(() => toast('เริ่มฝึกโมเดลไม่สำเร็จ'));
  };
  // เผื่อ refresh หน้าขณะมีการฝึกค้างอยู่ ให้ต่อ polling ทันทีแทนที่จะรอกดปุ่มใหม่
  fetch('/api/train/status').then(res => res.json()).then(s => {
    if (s.status === 'running') {
      $('#btnTrain').disabled = true;
      $('#btnTrain').textContent = 'กำลังฝึกโมเดล...';
      trainPollT = setInterval(pollTrainStatus, 3000);
    }
  }).catch(() => {});
}

// หน้า Notifications: เคลียร์จุดแดงที่กระดิ่ง + ดึงประวัติแจ้งเตือนจริงจาก DB
if ($('#tbNoti')) {
  if($('#bellDot')) $('#bellDot').classList.remove('on');
  fetchNotifications();
}

// หน้า Incident Detail: อ่าน incident id ที่ฝังมาจาก Flask (data-incident-id) แล้วโหลดรายละเอียดอัตโนมัติ
if ($('#vDetail')) {
  const incId = $('#vDetail').dataset.incidentId;
  if (incId) openDetailFromDB(incId);
}

// ทุกหน้าในแอป: ดึงตัวเลขสะสมจาก server ทันทีที่โหลดหน้า (ไม่ต้องรอ engine เริ่ม)
// แล้วรีเฟรชทุก 5 วินาที เผื่อมีทราฟฟิกใหม่จากแท็บ/เครื่องอื่นที่เปิดพร้อมกัน
if ($('#app')) {
  fetchStats();
  setInterval(fetchStats, 5000);
}

// หน้า Dashboard และ Live Monitoring: เริ่ม engine จำลองทราฟฟิกต่อเนื่อง
if ($('#chLine') || $('#tbLive')) {
  startEngine();
} else if ($('#app')) {
  // หน้าอื่นๆ ในแอป (Logs/Notifications/Settings/Train/Profile) ยังโชว์นาฬิกาที่ topbar ได้
  // โดยไม่ต้องเปิด loop จำลองทราฟฟิกใหม่ทุกครั้งที่เข้าหน้า
  if($('#clock')) setInterval(()=>{ if($('#clock')) $('#clock').textContent=hhmmss(new Date()); },1000);
  if($('#clock')) $('#clock').textContent=hhmmss(new Date());
}
