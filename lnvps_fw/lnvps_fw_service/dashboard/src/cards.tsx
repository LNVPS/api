import { useState, useEffect, useCallback } from "preact/hooks";
import { api, authHeaders } from "./api";
import type { InterfaceInfo, Limits, Mitigation, TrackedSource, SourcesPage, PortsPage } from "./api";
import { fmtn, fmtbps, fmtUnit, parseUnit, timeStr, dropColor } from "./format";
import { LoadBar, Table, Pager, PagedTable, Section, Modal, flagCell } from "./ui";

const FLAGS: [number, string][] = [[1, "PORT_FILTER"], [2, "SYN_PROXY"], [4, "RATE_CAPS"], [8, "SOURCE_BLOCK"]];

// --- Connect screen: shown until the first successful load. Holds its own
// input state so typing the token doesn't touch the app token / fire requests;
// the token is only committed (and saved) when Connect is pressed. ---
export function Login({ initial, onConnect, msg }: {
  initial: string; onConnect: (t: string) => void; msg?: string;
}) {
  const [val, setVal] = useState(initial);
  const go = () => onConnect(val.trim());
  return (
    <div class="connect-wrap"><div class="connect">
      <div class="k">lnvps<b>_fw</b></div>
      <div class="d">XDP / eBPF packet-defense datapath</div>
      <input type="password" placeholder="API token" value={val} autoFocus
        onInput={(e) => setVal((e.target as HTMLInputElement).value)}
        onKeyDown={(e) => e.key === "Enter" && go()} />
      <button onClick={go}>Connect</button>
      <div class="msg err">{msg || ""}</div>
    </div></div>
  );
}

// --- Live-editable detection thresholds ---
export function LimitsCard({ token, nics }: { token: string; nics?: InterfaceInfo[] }) {
  const [f, setF] = useState<Limits | null>(null);
  const [msg, setMsg] = useState("");
  const [txt, setTxt] = useState<Record<string, string>>({});
  useEffect(() => { (async () => { try { setF(await api<Limits>("/api/v1/limits", token)); setTxt({}); } catch { /* */ } })(); }, [token]);
  if (!f) return <div class="muted">…</div>;

  // Aggregate line rate (bit/s): only host/filter NICs (ingress/filter path).
  const capBits = (nics || []).filter((n) => n.role !== "learn").reduce((a, n) => a + (n.speed_mbps ? n.speed_mbps * 1e6 : 0), 0);
  const lineStr = capBits >= 1e9 ? capBits / 1e9 + "G" : capBits >= 1e6 ? capBits / 1e6 + "M" : "";
  const overCap = (bytes: number) => capBits > 0 && bytes * 8 > capBits;

  const badUnit = (v?: string) => v != null && (v.trim() === "" || !isFinite(parseUnit(v)));
  const errStyle = (v?: string) => (badUnit(v) ? { borderColor: "#ff5d6c" } : undefined);
  const setNum = (k: keyof Limits) => (e: Event) =>
    setF({ ...f, [k]: Math.max(0, Math.floor(+(e.target as HTMLInputElement).value || 0)) });
  const fld = (k: keyof Limits, label: string) => (
    <label>{label}<input type="number" min="1" value={f[k]} onInput={setNum(k)} /></label>
  );
  // Count field (k/M/G suffixes).
  const rateFld = (k: keyof Limits, label: string) => (
    <label>{label}
      <input value={txt[k] ?? fmtUnit(f[k])} placeholder="e.g. 100k" style={errStyle(txt[k])}
        onInput={(e) => { const v = (e.target as HTMLInputElement).value; setTxt({ ...txt, [k]: v }); const n = parseUnit(v); if (isFinite(n) && n >= 0) setF({ ...f, [k]: n }); }} />
    </label>
  );
  // Bandwidth field: entered in bit/s, stored as bytes/s (÷8).
  const bpsFld = (k: keyof Limits, label: string) => (
    <label>{label}
      <input value={txt[k] ?? fmtUnit((f[k] || 0) * 8)} placeholder="e.g. 8G" style={errStyle(txt[k])}
        onInput={(e) => { const v = (e.target as HTMLInputElement).value; setTxt({ ...txt, [k]: v }); const bits = parseUnit(v); if (isFinite(bits) && bits >= 0) setF({ ...f, [k]: Math.round(bits / 8) }); }} />
    </label>
  );
  const anyInvalid = Object.values(txt).some(badUnit);
  const save = async () => {
    if (anyInvalid) { setMsg("fix the highlighted field(s) — use a number with an optional k/M/G suffix"); return; }
    setMsg("saving…");
    try {
      const r = await fetch("/api/v1/limits", { method: "PUT", headers: authHeaders(token), body: JSON.stringify(f) });
      setMsg(r.ok ? "saved ✓" : "error " + r.status + ": " + (await r.text()));
    } catch (e) { setMsg((e as Error).message); }
  };
  const reload = async () => { setMsg(""); try { setF(await api<Limits>("/api/v1/limits", token)); setTxt({}); } catch { /* */ } };
  // A per-IP threshold above the prefix (aggregate) threshold is nonsensical:
  // a single IP hitting it means the aggregate already passed the lower prefix
  // limit, so the prefix trips first and the IP-level rule can never engage.
  const overPrefix = [
    f.pps > f.net_pps ? "pps" : "",
    f.syn_pps > f.net_syn_pps ? "syn/s" : "",
    f.bps > f.net_bps ? "bit/s" : "",
  ].filter(Boolean);
  return (
    <div class="limits">
      {rateFld("pps", "IP pps")}{rateFld("syn_pps", "IP syn/s")}{bpsFld("bps", "IP bit/s")}
      {rateFld("net_pps", "prefix pps")}{rateFld("net_syn_pps", "prefix syn/s")}{bpsFld("net_bps", "prefix bit/s")}
      {fld("exit_pct", "exit %")}{fld("cooldown_secs", "cooldown s")}
      {rateFld("src_rate_pps", "src block pps")}{fld("src_exit_pct", "src exit %")}{fld("src_cooldown_secs", "src cooldown s")}
      <div class="act">
        <button onClick={save} disabled={anyInvalid}>save</button>
        <button class="ghost" onClick={reload}>reset</button>
        <span class="muted">{msg}</span>
      </div>
      {overPrefix.length > 0 && (
        <div class="err" style={{ width: "100%", fontSize: ".72rem" }}>
          ⚠ IP {overPrefix.join(" & ")} limit{overPrefix.length > 1 ? "s" : ""} above the prefix limit — the prefix trips first, so IP-level mitigation can't engage
        </div>
      )}
      {capBits > 0 && (overCap(f.bps) || overCap(f.net_bps)) && (
        <div class="err" style={{ width: "100%", fontSize: ".72rem" }}>
          ⚠ {overCap(f.bps) ? "IP" : ""}{overCap(f.bps) && overCap(f.net_bps) ? " & " : ""}{overCap(f.net_bps) ? "prefix" : ""}
          {" bit/s limit exceeds the " + lineStr + " line rate — can never trip"}
        </div>
      )}
    </div>
  );
}

// --- Active mitigations: same live row format as tracked IPs + overrides ---
export function MitigationsCard({ token, mitigations, onChange }: {
  token: string; mitigations: Mitigation[]; onChange: () => void;
}) {
  const [show, setShow] = useState(false);
  const [cidr, setCidr] = useState("");
  const [flags, setFlags] = useState(1);
  const [msg, setMsg] = useState("");
  const hdr = authHeaders(token);
  const add = async () => {
    setMsg("saving…");
    try {
      const r = await fetch("/api/v1/mitigations", { method: "POST", headers: hdr, body: JSON.stringify({ cidr, flags }) });
      if (r.ok) { setShow(false); setCidr(""); setFlags(1); setMsg(""); onChange(); }
      else setMsg("error " + r.status + ": " + (await r.text()));
    } catch (e) { setMsg((e as Error).message); }
  };
  const del = async (c: string) => { try { await fetch("/api/v1/mitigations?cidr=" + encodeURIComponent(c), { method: "DELETE", headers: hdr }); onChange(); } catch { /* */ } };
  const bin = (c: string) => <button class="binbtn" title="remove override" onClick={() => del(c)}>🗑</button>;
  const meta = (m: Mitigation) => m.manual ? <span><span class="tag">manual</span> {timeStr(m.since_unix)}</span> : timeStr(m.since_unix);
  const rows = mitigations.map((m) => [
    m.cidr, fmtn(m.rx_pps), fmtbps(m.rx_bps), fmtn(m.tx_pps), fmtbps(m.tx_bps),
    fmtn(m.rx_syn_pps), fmtn(m.rx_drop_pps), <LoadBar pct={m.rx_drop_pct} color={dropColor} />,
    <LoadBar pct={m.load_pct} />, flagCell(m.flags), meta(m), m.manual ? bin(m.cidr) : "",
  ]);
  return (
    <div>
      <div style={{ marginBottom: ".5rem" }}><button onClick={() => { setShow(true); setMsg(""); }}>+ add override</button></div>
      <PagedTable cols={["cidr", "rx pps", "rx bps", "tx pps", "tx bps", "syn/s", "drop/s", "drop%", "load", "flags", "since", ""]} rows={rows} />
      {show && (
        <Modal title="Force-mitigate a destination" onClose={() => setShow(false)}>
          <label>CIDR<input value={cidr} placeholder="203.0.113.7/32" onInput={(e) => setCidr((e.target as HTMLInputElement).value)} /></label>
          <div>{FLAGS.map(([b, n]) => (
            <label class="chk"><input type="checkbox" checked={(flags & b) !== 0}
              onChange={(e) => setFlags((e.target as HTMLInputElement).checked ? flags | b : flags & ~b)} />{n}</label>
          ))}</div>
          <div class="act">
            <button onClick={add} disabled={!cidr}>add</button>
            <button class="ghost" onClick={() => setShow(false)}>cancel</button>
            <span class="muted err">{msg}</span>
          </div>
        </Modal>
      )}
    </div>
  );
}

// --- Sources: unified list of rate-tracked sources (normal/dropping/cooling)
// + manual blocks. Server-paginated + filtered. Auto "blocks" are just the
// dropping/cooling rows here — there is no separate block list. ---
export function SourcesCard({ token }: { token: string }) {
  const PAGE = 50;
  const [show, setShow] = useState(false);
  const [cidr, setCidr] = useState("");
  const [msg, setMsg] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const [data, setData] = useState<SourcesPage>({ total: 0, offset: 0, limit: PAGE, items: [] });
  const hdr = authHeaders(token);
  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ offset: String(page * PAGE), limit: String(PAGE), q });
      setData(await api<SourcesPage>("/api/v1/sources?" + params, token));
    } catch { /* surfaced by the main poller */ }
  }, [token, q, page]);
  useEffect(() => { load(); const id = setInterval(load, 3000); return () => clearInterval(id); }, [load]);
  const add = async () => {
    setMsg("saving…");
    try {
      const r = await fetch("/api/v1/blocks", { method: "POST", headers: hdr, body: JSON.stringify({ cidr }) });
      if (r.ok) { setShow(false); setCidr(""); setMsg(""); load(); } else setMsg("error " + r.status + ": " + (await r.text()));
    } catch (e) { setMsg((e as Error).message); }
  };
  const del = async (c: string) => { try { await fetch("/api/v1/blocks?cidr=" + encodeURIComponent(c), { method: "DELETE", headers: hdr }); load(); } catch { /* */ } };
  const bin = (c: string) => <button class="binbtn" title="remove block" onClick={() => del(c)}>🗑</button>;
  const stateCell = (s: TrackedSource) => s.manual
    ? <span class="tag">pinned</span>
    : s.state === "cooling" ? <span style={{ color: "#f5b13d" }}>cooling</span>
      : s.state === "dropping" ? <span style={{ color: "#ff5d6c" }}>dropping</span>
        : <span style={{ color: "#6fcf7f" }}>normal</span>;
  const pages = Math.max(1, Math.ceil(data.total / PAGE));
  const rows = data.items.map((s) => [
    s.ip, <span class="tag">{s.manual ? "manual" : "auto"}</span>, stateCell(s),
    s.manual ? "—" : fmtn(s.pps), s.manual ? "—" : s.age_secs + "s", s.manual ? bin(s.ip) : "",
  ]);
  return (
    <div>
      <div style={{ marginBottom: ".5rem", display: "flex", gap: ".5rem", alignItems: "center" }}>
        <button onClick={() => { setShow(true); setMsg(""); }}>+ block source</button>
        <input placeholder="filter ip" value={q} onInput={(e) => { setPage(0); setQ((e.target as HTMLInputElement).value); }} />
      </div>
      <div class="scroll"><Table cols={["source", "kind", "state", "pps", "age", ""]} rows={rows} /></div>
      {data.total > PAGE && <Pager page={Math.min(page, pages - 1)} pages={pages} total={data.total} onPage={setPage} />}
      {show && (
        <Modal title="Block a source CIDR" onClose={() => setShow(false)}>
          <label>CIDR<input value={cidr} placeholder="45.134.26.0/24" onInput={(e) => setCidr((e.target as HTMLInputElement).value)} /></label>
          <div class="act">
            <button onClick={add} disabled={!cidr}>block</button>
            <button class="ghost" onClick={() => setShow(false)}>cancel</button>
            <span class="muted err">{msg}</span>
          </div>
        </Modal>
      )}
    </div>
  );
}

// --- Learned open ports: server-paginated + filtered ---
export function PortsCard({ token }: { token: string }) {
  const PAGE = 50;
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const [data, setData] = useState<PortsPage>({ total: 0, offset: 0, limit: PAGE, items: [] });
  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ offset: String(page * PAGE), limit: String(PAGE), q });
      setData(await api<PortsPage>("/api/v1/ports?" + params, token));
    } catch { /* */ }
  }, [token, q, page]);
  useEffect(() => { load(); const id = setInterval(load, 5000); return () => clearInterval(id); }, [load]);
  const pages = Math.max(1, Math.ceil(data.total / PAGE));
  const rows = data.items.map((p) => [p.ip, p.port, p.proto, p.age_secs + "s"]);
  return (
    <Section wide title="Learned open ports" extra={"(" + data.total + ")"}>
      <input placeholder="filter ip/port/proto" value={q}
        onInput={(e) => { setPage(0); setQ((e.target as HTMLInputElement).value); }} style={{ marginBottom: ".5rem" }} />
      <div class="scroll"><Table cols={["ip", "port", "proto", "age"]} rows={rows} /></div>
      {data.total > PAGE && <Pager page={Math.min(page, pages - 1)} pages={pages} total={data.total} onPage={setPage} />}
    </Section>
  );
}
