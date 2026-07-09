import { h, render } from 'preact';
import { useState, useEffect, useRef, useCallback } from 'preact/hooks';
import htm from 'htm';
const html = htm.bind(h);

const FLAGS = [[1,'PORT_FILTER'],[2,'SYN_PROXY'],[4,'RATE_CAPS'],[8,'SOURCE_BLOCK']];
const flagStr = f => { const o = FLAGS.filter(([b])=>f&b).map(([,n])=>n); return o.length?o.join('|'):'none'; };
const fmtn = n => n>=1e6 ? (n/1e6).toFixed(1)+'M' : n>=1e3 ? (n/1e3).toFixed(1)+'k' : ''+n;
const fmtbps = b => { const x=b*8; return x>=1e9?(x/1e9).toFixed(2)+' Gb/s':x>=1e6?(x/1e6).toFixed(1)+' Mb/s':x>=1e3?(x/1e3).toFixed(0)+' kb/s':x+' b/s'; };
const flagCell = f => html`<span class="flag">${flagStr(f)}</span>`;
const time = t => new Date(t*1000).toLocaleTimeString();
const loadColor = p => p>=100?'#ff6b6b':p>=80?'#f0b429':p>=50?'#7fd1ff':'#3fb950';
function LoadBar({ pct }) {
  const p = Math.min(pct, 100), c = loadColor(pct);
  return html`<span class="barwrap">
    <span class="bar"><span class="fill" style=${'width:'+p+'%;background:'+c}></span></span>
    <span style=${'color:'+c+';font-weight:600'}>${pct}%</span></span>`;
}


async function api(path, token) {
  const r = await fetch(path, { headers: token ? { Authorization: 'Bearer ' + token } : {} });
  if (!r.ok) throw new Error(path.split('?')[0] + ' -> ' + r.status);
  return r.status === 204 ? null : r.json();
}

function Table({ cols, rows }) {
  if (!rows.length) return html`<div class="muted">none</div>`;
  return html`<table>
    <thead><tr>${cols.map(c => html`<th>${c}</th>`)}</tr></thead>
    <tbody>${rows.map(r => html`<tr>${r.map(c => html`<td>${c}</td>`)}</tr>`)}</tbody>
  </table>`;
}

function Pager({ page, pages, total, onPage }) {
  return html`<div class="pager">
    <button class="ghost" disabled=${page<=0} onClick=${()=>onPage(page-1)}>‹ prev</button>
    <span class="muted">page ${page+1}/${pages} · ${total} rows</span>
    <button class="ghost" disabled=${page>=pages-1} onClick=${()=>onPage(page+1)}>next ›</button>
  </div>`;
}

// Client-side paginated table (for bounded datasets).
function PagedTable({ cols, rows, pageSize = 50 }) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const p = Math.min(page, pages - 1);
  const slice = rows.slice(p * pageSize, p * pageSize + pageSize);
  return html`<div class="scroll"><${Table} cols=${cols} rows=${slice} /></div>
    ${rows.length > pageSize && html`<${Pager} page=${p} pages=${pages} total=${rows.length} onPage=${setPage} />`}`;
}

function Section({ title, extra, children, wide }) {
  return html`<section class=${wide?'wide':''}>
    <h2>${title}${extra?html`<span class="muted">${extra}</span>`:null}</h2>${children}</section>`;
}

// Live-editable detection thresholds. Seeds from GET /limits once so the 2s
// poll doesn't clobber edits; PUT on save.
function LimitsCard({ token }) {
  const [f, setF] = useState(null);
  const [msg, setMsg] = useState('');
  useEffect(() => { (async () => { try { setF(await api('/api/v1/limits', token)); } catch (e) {} })(); }, [token]);
  if (!f) return html`<div class="muted">…</div>`;
  const num = k => e => setF({ ...f, [k]: Math.max(0, Math.floor(+e.target.value || 0)) });
  const fld = (k, label) => html`<label>${label}<input type="number" min="1" value=${f[k]} onInput=${num(k)} /></label>`;
  const save = async () => {
    setMsg('saving…');
    try {
      const r = await fetch('/api/v1/limits', { method: 'PUT',
        headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify(f) });
      setMsg(r.ok ? 'saved ✓' : 'error ' + r.status + ': ' + (await r.text()));
    } catch (e) { setMsg(e.message); }
  };
  const reload = async () => { setMsg(''); try { setF(await api('/api/v1/limits', token)); } catch (e) {} };
  return html`<div class="limits">
    ${fld('pps','IP pps')}${fld('syn_pps','IP syn/s')}${fld('bps','IP bytes/s')}
    ${fld('net_pps','prefix pps')}${fld('net_syn_pps','prefix syn/s')}${fld('net_bps','prefix bytes/s')}
    ${fld('exit_pct','exit %')}${fld('cooldown_secs','cooldown s')}
    <div class="act"><button onClick=${save}>save</button><button class="ghost" onClick=${reload}>reset</button>
      <span class="muted">${msg}</span></div>
  </div>`;
}

// Small modal helper (backdrop-dismissable).
function Modal({ title, onClose, children }) {
  return html`<div class="modal-bg" onClick=${e => e.target.className === 'modal-bg' && onClose()}>
    <div class="modal"><h3>${title}</h3>${children}</div></div>`;
}

// Active mitigations table + add/delete of manual dest overrides (force-mitigate
// a destination). Auto-detected rows are read-only; manual rows get a delete.
function MitigationsCard({ token, mitigations, onChange }) {
  const [show, setShow] = useState(false), [cidr, setCidr] = useState(''), [flags, setFlags] = useState(1), [msg, setMsg] = useState('');
  const hdr = { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' };
  const add = async () => { setMsg('saving…'); try {
      const r = await fetch('/api/v1/mitigations', { method: 'POST', headers: hdr, body: JSON.stringify({ cidr, flags }) });
      if (r.ok) { setShow(false); setCidr(''); setFlags(1); setMsg(''); onChange && onChange(); } else setMsg('error ' + r.status + ': ' + (await r.text()));
    } catch (e) { setMsg(e.message); } };
  const del = async c => { try { await fetch('/api/v1/mitigations?cidr=' + encodeURIComponent(c), { method: 'DELETE', headers: hdr }); onChange && onChange(); } catch (e) {} };
  const bin = c => html`<button class="binbtn" title="remove override" onClick=${() => del(c)}>🗑</button>`;
  const rows = mitigations.map(m => [m.cidr, flagCell(m.flags), time(m.since_unix), m.manual ? html`<span class="tag">manual</span>` : '',
    fmtn(m.peak_pps), fmtbps(m.peak_bps), fmtn(m.peak_syn_pps), m.manual ? bin(m.cidr) : '']);
  return html`<div>
    <div style="margin-bottom:.5rem"><button onClick=${() => { setShow(true); setMsg(''); }}>+ add override</button></div>
    <${PagedTable} cols=${['cidr','flags','since','manual','peak pps','peak bps','peak syn/s','']} rows=${rows} />
    ${show && html`<${Modal} title="Force-mitigate a destination" onClose=${() => setShow(false)}>
      <label>CIDR<input value=${cidr} placeholder="203.0.113.7/32" onInput=${e => setCidr(e.target.value)} /></label>
      <div>${FLAGS.map(([b, n]) => html`<label class="chk"><input type="checkbox" checked=${(flags & b) !== 0}
        onChange=${e => setFlags(e.target.checked ? flags | b : flags & ~b)} />${n}</label>`)}</div>
      <div class="act"><button onClick=${add} disabled=${!cidr}>add</button>
        <button class="ghost" onClick=${() => setShow(false)}>cancel</button><span class="muted err">${msg}</span></div>
    </${Modal}>`}
  </div>`;
}

// Source-block table: server-paginated + filtered (the block set can be very
// large). Auto blocks come from the per-source state machine and show their
// live pps and state (dropping = actively over-rate, cooling = below exit,
// counting down to release); manual blocks (add via modal, delete per row) drop
// an attacker CIDR outright.
function BlocksCard({ token }) {
  const PAGE = 50;
  const [show, setShow] = useState(false), [cidr, setCidr] = useState(''), [msg, setMsg] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(0);
  const [data, setData] = useState({ total: 0, items: [] });
  const hdr = { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' };
  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ offset: page*PAGE, limit: PAGE, q });
      setData(await api('/api/v1/blocks?' + params, token));
    } catch (e) { /* surfaced by the main poller */ }
  }, [token, q, page]);
  useEffect(() => { load(); const id = setInterval(load, 3000); return () => clearInterval(id); }, [load]);
  const add = async () => { setMsg('saving…'); try {
      const r = await fetch('/api/v1/blocks', { method: 'POST', headers: hdr, body: JSON.stringify({ cidr }) });
      if (r.ok) { setShow(false); setCidr(''); setMsg(''); load(); } else setMsg('error ' + r.status + ': ' + (await r.text()));
    } catch (e) { setMsg(e.message); } };
  const del = async c => { try { await fetch('/api/v1/blocks?cidr=' + encodeURIComponent(c), { method: 'DELETE', headers: hdr }); load(); } catch (e) {} };
  const bin = c => html`<button class="binbtn" title="remove block" onClick=${() => del(c)}>🗑</button>`;
  const stateCell = b => b.manual ? html`<span class="tag">pinned</span>`
    : b.cooling ? html`<span style="color:#f0b429">cooling</span>`
    : html`<span style="color:#ff6b6b">dropping</span>`;
  const pages = Math.max(1, Math.ceil(data.total / PAGE));
  const rows = data.items.map(b => [b.cidr, html`<span class="tag">${b.manual ? 'manual' : 'auto'}</span>`,
    stateCell(b), b.manual ? '—' : fmtn(b.pps), b.manual ? '—' : b.age_secs + 's', b.manual ? bin(b.cidr) : '']);
  return html`<div>
    <div style="margin-bottom:.5rem;display:flex;gap:.5rem;align-items:center">
      <button onClick=${() => { setShow(true); setMsg(''); }}>+ block source</button>
      <input placeholder="filter cidr" value=${q} onInput=${e => { setPage(0); setQ(e.target.value); }} /></div>
    <div class="scroll"><${Table} cols=${['cidr','kind','state','pps','age','']} rows=${rows} /></div>
    ${data.total > PAGE && html`<${Pager} page=${Math.min(page,pages-1)} pages=${pages} total=${data.total} onPage=${setPage} />`}
    ${show && html`<${Modal} title="Block a source CIDR" onClose=${() => setShow(false)}>
      <label>CIDR<input value=${cidr} placeholder="45.134.26.0/24" onInput=${e => setCidr(e.target.value)} /></label>
      <div class="act"><button onClick=${add} disabled=${!cidr}>block</button>
        <button class="ghost" onClick=${() => setShow(false)}>cancel</button><span class="muted err">${msg}</span></div>
    </${Modal}>`}
  </div>`;
}

// Server-side paginated + filtered learned-ports table.
function PortsCard({ token }) {
  const PAGE = 50;
  const [q, setQ] = useState('');
  const [page, setPage] = useState(0);
  const [data, setData] = useState({ total: 0, items: [] });
  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ offset: page*PAGE, limit: PAGE, q });
      const d = await api('/api/v1/ports?' + params, token);
      setData(d);
    } catch (e) { /* surfaced by the main poller */ }
  }, [token, q, page]);
  useEffect(() => { load(); const id = setInterval(load, 5000); return () => clearInterval(id); }, [load]);
  const pages = Math.max(1, Math.ceil(data.total / PAGE));
  const rows = data.items.map(p => [p.ip, p.port, p.proto, p.age_secs + 's']);
  return html`<${Section} wide=true title="Learned open ports" extra=${'(' + data.total + ')'}>
    <input placeholder="filter ip/port/proto" value=${q}
      onInput=${e => { setPage(0); setQ(e.target.value); }} style="margin-bottom:.5rem" />
    <div class="scroll"><${Table} cols=${['ip','port','proto','age']} rows=${rows} /></div>
    ${data.total > PAGE && html`<${Pager} page=${Math.min(page,pages-1)} pages=${pages} total=${data.total} onPage=${setPage} />`}
  </${Section}>`;
}

function App() {
  const [token, setTokenState] = useState(localStorage.getItem('fwtoken') || '');
  const [auto, setAuto] = useState(true);
  const [d, setD] = useState({ status: null, tracked: [], prefixes: [], mitigations: [], rules: { protected: [], overrides: [] }, upgrade: null, err: '' });
  const [upMsg, setUpMsg] = useState('');
  const [events, setEvents] = useState([]);
  const cursor = useRef(0);
  const tokenRef = useRef(token);
  tokenRef.current = token;

  const refresh = useCallback(async () => {
    const t = tokenRef.current;
    try {
      const [status, tracked, prefixes, mitigations, rules, upgrade] = await Promise.all([
        api('/api/v1/status', t), api('/api/v1/tracked', t), api('/api/v1/prefixes', t),
        api('/api/v1/mitigations', t), api('/api/v1/rules', t),
        api('/api/v1/upgrade', t),
      ]);
      const ev = await api('/api/v1/events?since=' + cursor.current, t);
      if (ev.events.length) { cursor.current = ev.cursor; setEvents(e => [...ev.events.slice().reverse(), ...e].slice(0, 500)); }
      setD({ status, tracked, prefixes, mitigations, rules, upgrade, err: '' });
    } catch (e) { setD(x => ({ ...x, err: e.message })); }
  }, []);

  useEffect(() => {
    refresh();
    if (!auto) return;
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  }, [auto, token, refresh]);

  const save = () => { localStorage.setItem('fwtoken', token); cursor.current = 0; setEvents([]); refresh(); };
  const doUpgrade = async () => {
    if (!confirm('Download & install ' + d.upgrade.latest + ' and restart the service?')) return;
    setUpMsg('upgrading… the service will restart shortly');
    try {
      const r = await fetch('/api/v1/upgrade', { method: 'POST', headers: { Authorization: 'Bearer ' + token } });
      if (!r.ok) setUpMsg('upgrade failed: ' + r.status + ' ' + (await r.text()));
    } catch (e) { setUpMsg('upgrade error: ' + e.message); }
  };
  const s = d.status;
  const t0 = s && s.totals;
  const summary = d.err ? html`<span class="err">${d.err}</span>`
    : s ? html`<span class="muted">up ${s.uptime_secs}s · ${s.active_mitigations} active · ${s.learned_ports} ports</span>`
    : html`<span class="muted">disconnected</span>`;
  const dropCell = pct => html`<span style=${'color:'+loadColor(pct)+';font-weight:600'}>${pct}%</span>`;

  const trackedRows = d.tracked.map(t => [t.ip, fmtn(t.rx_pps), fmtbps(t.rx_bps), fmtn(t.tx_pps), fmtbps(t.tx_bps),
    fmtn(t.rx_syn_pps), fmtn(t.rx_drop_pps), dropCell(t.rx_drop_pct), html`<${LoadBar} pct=${t.load_pct} />`,
    t.mitigating ? flagCell(t.flags) : 'ok']);
  const prefixRows = d.prefixes.map(p => [p.cidr, fmtn(p.rx_pps), fmtbps(p.rx_bps), fmtn(p.tx_pps), fmtbps(p.tx_bps),
    fmtn(p.rx_syn_pps), fmtn(p.rx_drop_pps), dropCell(p.rx_drop_pct), html`<${LoadBar} pct=${p.load_pct} />`,
    p.mitigating ? flagCell(p.flags) : 'ok']);
  const evRows = events.map(e => [e.seq, time(e.ts_unix), e.kind, e.cidr, flagCell(e.flags), fmtn(e.pps), fmtn(e.syn_pps)]);

  return html`
    <header>
      <h1>lnvps_fw</h1>${summary}
      ${t0 ? html`<span class="totals">↓rx <b>${fmtn(t0.rx_pps)}</b> pps · <b>${fmtbps(t0.rx_bps)}</b> · ↑tx <b>${fmtn(t0.tx_pps)}</b> pps · <b>${fmtbps(t0.tx_bps)}</b> · <b>${fmtn(t0.rx_syn_pps)}</b> syn/s · drop <b style=${'color:'+loadColor(t0.rx_drop_pct)}>${t0.rx_drop_pct}%</b> (${fmtn(t0.rx_drop_pps)} pps)</span>` : null}
      ${d.upgrade && d.upgrade.available ? html`<button style="background:#3fb950" title="download & install ${d.upgrade.latest}, then restart"
        onClick=${doUpgrade}>⬆ upgrade ${d.upgrade.latest}</button>` : null}
      ${upMsg ? html`<span class="muted">${upMsg}</span>` : null}
      <span class="grow"></span>
      <input type="password" placeholder="API token" size="26" value=${token}
        onInput=${e => setTokenState(e.target.value)} onKeyDown=${e => e.key==='Enter' && save()} />
      <button onClick=${save}>connect</button>
      <label class="muted"><input type="checkbox" checked=${auto} onChange=${e => setAuto(e.target.checked)} /> auto</label>
      <button class="ghost" onClick=${refresh}>refresh</button>
    </header>
    <main>
      <${Section} wide=true title="Detection limits">
        <${LimitsCard} token=${token} />
      </${Section}>
      <${Section} wide=true title="Active mitigations" extra=${'('+d.mitigations.length+')'}>
        <${MitigationsCard} token=${token} mitigations=${d.mitigations} onChange=${refresh} />
      </${Section}>
      <${Section} wide=true title="Live tracked IPs" extra=${'('+d.tracked.length+')'}>
        <${PagedTable} cols=${['ip','rx pps','rx bps','tx pps','tx bps','syn/s','drop/s','drop%','load','state']} rows=${trackedRows} />
      </${Section}>
      <${Section} wide=true title="Protected prefixes" extra=${'('+d.prefixes.length+')'}>
        <${PagedTable} cols=${['prefix','rx pps','rx bps','tx pps','tx bps','syn/s','drop/s','drop%','load','state']} rows=${prefixRows} />
      </${Section}>
      <${Section} wide=true title="Source blocks">
        <${BlocksCard} token=${token} />
      </${Section}>
      <${PortsCard} token=${token} />
      <${Section} wide=true title="Events" extra=${'('+events.length+')'}>
        <${PagedTable} cols=${['seq','time','kind','cidr','flags','pps','syn/s']} rows=${evRows} />
      </${Section}>
    </main>`;
}

render(html`<${App} />`, document.getElementById('app'));
