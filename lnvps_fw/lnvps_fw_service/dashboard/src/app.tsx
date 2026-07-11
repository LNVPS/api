import { useState, useEffect, useRef, useCallback } from "preact/hooks";
import type { ComponentChildren } from "preact";
import { api } from "./api";
import type { Status, TrackedIp, PrefixLoad, Mitigation, FwEvent, RuleSet, UpgradeStatus } from "./api";
import { fmtn, fmtbps, timeStr, loadColor, dropColor } from "./format";
import { LoadBar, Sparkline, PagedTable, Section, flagCell } from "./ui";
import { Login, LimitsCard, MitigationsCard, BlocksCard, PortsCard } from "./cards";

interface Data {
  status: Status | null;
  tracked: TrackedIp[];
  prefixes: PrefixLoad[];
  mitigations: Mitigation[];
  rules: RuleSet;
  upgrade: UpgradeStatus | null;
  err: string;
}

const EMPTY: Data = {
  status: null, tracked: [], prefixes: [], mitigations: [],
  rules: { protected: [], overrides: [], source_blocks: [] }, upgrade: null, err: "",
};

// Baked in only for the demo image build (`VITE_DEMO_TOKEN=... bun run build`).
// When set, the dashboard seeds this token and auto-connects on load so the
// public demo needs no manual login. Empty in normal release builds, so the
// connect screen behaves as usual.
const DEMO_TOKEN = (import.meta.env.VITE_DEMO_TOKEN as string | undefined) || "";

export function App() {
  const [token, setToken] = useState(localStorage.getItem("fwtoken") || DEMO_TOKEN);
  const [auto, setAuto] = useState(true);
  const [d, setD] = useState<Data>(EMPTY);
  const [upMsg, setUpMsg] = useState("");
  const [events, setEvents] = useState<FwEvent[]>([]);
  const cursor = useRef(0);
  const tokenRef = useRef(token);
  tokenRef.current = token;
  const histRef = useRef<{ rx: number[]; tx: number[]; drop: number[] }>({ rx: [], tx: [], drop: [] });

  const refresh = useCallback(async () => {
    const t = tokenRef.current;
    if (!t) return; // no token -> don't poll (no spurious 401s behind the login)
    try {
      const [status, tracked, prefixes, mitigations, rules, upgrade] = await Promise.all([
        api<Status>("/api/v1/status", t), api<TrackedIp[]>("/api/v1/tracked", t),
        api<PrefixLoad[]>("/api/v1/prefixes", t), api<Mitigation[]>("/api/v1/mitigations", t),
        api<RuleSet>("/api/v1/rules", t), api<UpgradeStatus>("/api/v1/upgrade", t),
      ]);
      const ev = await api<{ events: FwEvent[]; cursor: number }>("/api/v1/events?since=" + cursor.current, t);
      if (ev.events.length) { cursor.current = ev.cursor; setEvents((e) => [...ev.events.slice().reverse(), ...e].slice(0, 500)); }
      const h = histRef.current, T = status.totals;
      h.rx.push(T.rx_bps); h.tx.push(T.tx_bps); h.drop.push(T.rx_drop_pct);
      [h.rx, h.tx, h.drop].forEach((a) => { while (a.length > 48) a.shift(); });
      setD({ status, tracked, prefixes, mitigations, rules, upgrade, err: "" });
    } catch (e) { setD((x) => ({ ...x, err: (e as Error).message })); }
  }, []);

  const connected = !!d.status;
  // One attempt on mount (with any saved token); if it fails we land on the
  // connect screen and DON'T keep polling (no spurious 401s behind the login).
  useEffect(() => { refresh(); }, [refresh]);
  // Poll only once connected.
  useEffect(() => {
    if (!auto || !connected) return;
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  }, [auto, connected, refresh]);

  // Commit + save the token only here (from the connect screen's submit).
  const connect = (tok: string) => {
    const t = tok.trim();
    setToken(t);
    tokenRef.current = t;
    localStorage.setItem("fwtoken", t);
    cursor.current = 0;
    setEvents([]);
    refresh();
  };
  const disconnect = () => { localStorage.removeItem("fwtoken"); setToken(""); histRef.current = { rx: [], tx: [], drop: [] }; setD((x) => ({ ...x, status: null, err: "" })); };
  // Force an immediate GitHub release check (bypasses the cached 6h status).
  const checkUpdates = async () => {
    setUpMsg("checking…");
    try {
      const u = await api<UpgradeStatus>("/api/v1/upgrade?check=true", token);
      setD((x) => ({ ...x, upgrade: u }));
      setUpMsg(u.available ? "" : u.error ? "check failed: " + u.error : "up to date (" + u.current + ")");
    } catch (e) { setUpMsg("check error: " + (e as Error).message); }
  };
  const doUpgrade = async () => {
    if (!d.upgrade || !confirm("Download & install " + d.upgrade.latest + " and restart the service?")) return;
    setUpMsg("upgrading… the service will restart shortly");
    try {
      const r = await fetch("/api/v1/upgrade", { method: "POST", headers: { Authorization: "Bearer " + token } });
      if (!r.ok) setUpMsg("upgrade failed: " + r.status + " " + (await r.text()));
    } catch (e) { setUpMsg("upgrade error: " + (e as Error).message); }
  };

  const s = d.status;
  // Not connected yet -> connect screen, not a page of empty widgets.
  if (!s) return <Login initial={token} onConnect={connect} msg={d.err} />;

  const t0 = s.totals;
  const hist = histRef.current;
  const fmtspeed = (m: number) => (m >= 1000 ? m / 1000 + "G" : m + "M");
  const nicStr = s.nics && s.nics.length
    ? s.nics.map((n) => n.name + (n.speed_mbps ? "@" + fmtspeed(n.speed_mbps) : "") + (n.role && n.role !== "host" ? "/" + n.role : "")).join(" ")
    : "";
  const capBits = (s.nics || []).filter((n) => n.role !== "learn").reduce((a, n) => a + (n.speed_mbps ? n.speed_mbps * 1e6 : 0), 0);
  const lineStr = capBits >= 1e9 ? capBits / 1e9 + "G" : capBits >= 1e6 ? capBits / 1e6 + "M" : "";
  const util = (bytes: number) => (capBits > 0 ? Math.min(100, Math.round((bytes * 8) / capBits * 100)) : null);
  const satBar = (bytes: number) => {
    const u = util(bytes);
    return u == null ? null : (
      <div class="sat">
        <div class="satbar"><span style={{ width: u + "%", background: loadColor(u) }} /></div>
        <span class="satlbl">{u}% of {lineStr} line</span>
      </div>
    );
  };
  const meter = (dir: string, lbl: string, color: string, big: string, sub: string, spark: ComponentChildren, sat: ComponentChildren) => (
    <div class="meter">
      <span class="dir" style={{ color }}>{dir}</span>
      <div class="stack"><span class="lbl">{lbl}</span><span class="big" style={{ color }}>{big}</span><span class="sub">{sub}</span></div>
      {spark}{sat}
    </div>
  );

  const dropCell = (pct: number) => <LoadBar pct={pct} color={dropColor} />;
  const trackedRows = d.tracked.map((t) => [
    t.ip, fmtn(t.rx_pps), fmtbps(t.rx_bps), fmtn(t.tx_pps), fmtbps(t.tx_bps),
    fmtn(t.rx_syn_pps), fmtn(t.rx_drop_pps), dropCell(t.rx_drop_pct), <LoadBar pct={t.load_pct} />,
    t.mitigating ? flagCell(t.flags) : "ok",
  ]);
  const prefixRows = d.prefixes.map((p) => [
    p.cidr, fmtn(p.rx_pps), fmtbps(p.rx_bps), fmtn(p.tx_pps), fmtbps(p.tx_bps),
    fmtn(p.rx_syn_pps), fmtn(p.rx_drop_pps), dropCell(p.rx_drop_pct), <LoadBar pct={p.load_pct} />,
    p.mitigating ? flagCell(p.flags) : "ok",
  ]);
  const evTip = "rate at the event — the episode peak on a stop";
  const evCols = ["seq", "time", "kind", "cidr", "flags",
    <span title={"packets/s: " + evTip}>pps</span>, <span title={"bit/s: " + evTip}>bps</span>, <span title={"SYN/s: " + evTip}>syn/s</span>];
  const evRows = events.map((e) => [e.seq, timeStr(e.ts_unix), e.kind, e.cidr, flagCell(e.flags), fmtn(e.pps), fmtbps(e.bps), fmtn(e.syn_pps)]);

  const posture = s.active_mitigations > 0
    ? <span class="chip atk">● under attack</span>
    : <span class="chip arm">● armed</span>;

  return (
    <>
      <header>
        <h1>lnvps<b>_fw</b></h1>
        {posture}
        <span class="muted">up {s.uptime_secs}s · {s.active_mitigations} active · {s.learned_ports} ports{nicStr ? " · " + nicStr : ""}</span>
        {d.err ? <span class="err">{d.err}</span> : null}
        {d.upgrade && d.upgrade.available
          ? <button title={"download & install " + d.upgrade.latest + ", then restart"} onClick={doUpgrade}>⬆ upgrade {d.upgrade.latest}</button>
          : null}
        {upMsg ? <span class="muted">{upMsg}</span> : null}
        <span class="grow" />
        <button class="ghost" title="Check for updates now" onClick={checkUpdates}>↻</button>
        <label class="muted"><input type="checkbox" checked={auto} onChange={(e) => setAuto((e.target as HTMLInputElement).checked)} /> auto</label>
        <button class="ghost" onClick={refresh}>refresh</button>
        <button class="ghost" onClick={disconnect}>disconnect</button>
      </header>
      <main>
        {t0 && (
          <section class="wide"><div class="traffic">
            {meter("↓", "rx · ingress", "#2fd4c4", fmtbps(t0.rx_bps), fmtn(t0.rx_pps) + " pps · " + fmtn(t0.rx_syn_pps) + " syn/s",
              <Sparkline data={hist.rx} color="#2fd4c4" />, satBar(t0.rx_bps))}
            {meter("↑", "tx · egress", "#9a86ff", fmtbps(t0.tx_bps), fmtn(t0.tx_pps) + " pps",
              <Sparkline data={hist.tx} color="#9a86ff" />, satBar(t0.tx_bps))}
            {meter("●", "dropped", dropColor(t0.rx_drop_pct), t0.rx_drop_pct + "%", fmtn(t0.rx_drop_pps) + " pps",
              <Sparkline data={hist.drop} color={dropColor(t0.rx_drop_pct)} max={100} />, null)}
          </div></section>
        )}
        <Section wide title="Detection limits"><LimitsCard token={token} nics={s.nics} /></Section>
        <Section wide title="Active mitigations" extra={"(" + d.mitigations.length + ")"}>
          <MitigationsCard token={token} mitigations={d.mitigations} onChange={refresh} />
        </Section>
        <Section wide title="Live tracked IPs" extra={"(" + d.tracked.length + ")"}>
          <PagedTable cols={["ip", "rx pps", "rx bps", "tx pps", "tx bps", "syn/s", "drop/s", "drop%", "load", "state"]} rows={trackedRows} />
        </Section>
        <Section wide title="Protected prefixes" extra={"(" + d.prefixes.length + ")"}>
          <PagedTable cols={["prefix", "rx pps", "rx bps", "tx pps", "tx bps", "syn/s", "drop/s", "drop%", "load", "state"]} rows={prefixRows} />
        </Section>
        <Section wide title="Source blocks"><BlocksCard token={token} /></Section>
        <PortsCard token={token} />
        <Section wide title="Events" extra={"(" + events.length + ")"}>
          <PagedTable cols={evCols} rows={evRows} />
        </Section>
      </main>
    </>
  );
}
