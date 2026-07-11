// Control-API types (mirror the Rust structs) + fetch helper.

export interface Totals {
  rx_pps: number; rx_bps: number; rx_syn_pps: number; rx_drop_pps: number;
  rx_drop_pct: number; tx_pps: number; tx_bps: number;
}
export interface InterfaceInfo { name: string; speed_mbps: number | null; role: string }
export interface Status {
  version: string; uptime_secs: number; interfaces: string[]; nics: InterfaceInfo[];
  protected_prefixes: number; active_mitigations: number; learned_ports: number;
  events_cursor: number; totals: Totals;
}
export interface TrackedIp {
  ip: string; rx_pps: number; rx_bps: number; rx_syn_pps: number; rx_drop_pps: number;
  tx_pps: number; tx_bps: number; rx_drop_pct: number; mitigating: boolean; flags: number; load_pct: number;
}
export interface PrefixLoad {
  cidr: string; rx_pps: number; rx_bps: number; rx_syn_pps: number; rx_drop_pps: number;
  tx_pps: number; tx_bps: number; rx_drop_pct: number; mitigating: boolean; flags: number; load_pct: number;
}
export interface Mitigation {
  cidr: string; flags: number; since_unix: number; manual: boolean;
  peak_pps: number; peak_bps: number; peak_syn_pps: number;
  rx_pps: number; rx_bps: number; rx_syn_pps: number; rx_drop_pps: number;
  tx_pps: number; tx_bps: number; rx_drop_pct: number; load_pct: number;
}
export interface SourceBlock { cidr: string; age_secs: number; pps: number; manual: boolean; cooling: boolean }
/** A row in the unified source list: tracked sources (any state) + manual blocks. */
export interface TrackedSource { ip: string; pps: number; state: "normal" | "dropping" | "cooling"; manual: boolean; age_secs: number }
export interface LearnedPort { ip: string; port: number; proto: string; age_secs: number }
export interface FwEvent {
  seq: number; kind: string; cidr: string; flags: number; ts_unix: number;
  pps: number; bps: number; syn_pps: number;
}
export interface Limits {
  pps: number; syn_pps: number; bps: number; net_pps: number; net_syn_pps: number;
  net_bps: number; exit_pct: number; cooldown_secs: number;
  src_rate_pps: number; src_exit_pct: number; src_cooldown_secs: number;
}
export interface UpgradeStatus {
  current: string; latest: string | null; available: boolean;
  deb_url: string | null; checked_at: number; error: string | null;
}
export interface Override { cidr: string; flags: number }
export interface RuleSet { protected: string[]; overrides: Override[]; source_blocks: string[] }
export interface BlocksPage { total: number; offset: number; limit: number; items: SourceBlock[] }
export interface SourcesPage { total: number; offset: number; limit: number; items: TrackedSource[] }
export interface PortsPage { total: number; offset: number; limit: number; items: LearnedPort[] }
export interface EventsResponse { events: FwEvent[]; cursor: number }

/** GET a JSON endpoint with bearer auth. Returns null on 204. Throws on !ok. */
export async function api<T = unknown>(path: string, token: string): Promise<T> {
  const r = await fetch(path, { headers: token ? { Authorization: "Bearer " + token } : {} });
  if (!r.ok) throw new Error(path.split("?")[0] + " -> " + r.status);
  return (r.status === 204 ? null : await r.json()) as T;
}

export const authHeaders = (token: string): Record<string, string> => ({
  Authorization: "Bearer " + token,
  "Content-Type": "application/json",
});
