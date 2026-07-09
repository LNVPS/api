// Formatting + color helpers shared across the dashboard.

export const FLAGS: [number, string][] = [
  [1, "PORT_FILTER"],
  [2, "SYN_PROXY"],
  [4, "RATE_CAPS"],
  [8, "SOURCE_BLOCK"],
];

export const flagStr = (f: number): string => {
  const o = FLAGS.filter(([b]) => f & b).map(([, n]) => n);
  return o.length ? o.join("|") : "none";
};

/** Compact count: 1_500_000 -> "1.5M". */
export const fmtn = (n: number): string =>
  n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "k" : "" + n;

/** Bytes/s -> bit/s display: 1e9 bytes -> "8.00 Gb/s". */
export const fmtbps = (b: number): string => {
  const x = b * 8;
  return x >= 1e9
    ? (x / 1e9).toFixed(2) + " Gb/s"
    : x >= 1e6
    ? (x / 1e6).toFixed(1) + " Mb/s"
    : x >= 1e3
    ? (x / 1e3).toFixed(0) + " kb/s"
    : x + " b/s";
};

const UNIT: Record<string, number> = { k: 1e3, m: 1e6, g: 1e9 };

/** Parse "100k" / "1.5M" / "2g" / "1000" -> integer; NaN if invalid. */
export const parseUnit = (s: string): number => {
  const m = String(s).trim().match(/^([\d.]+)\s*([kmgKMG]?)$/);
  if (!m) return NaN;
  const n = parseFloat(m[1]);
  return isFinite(n) ? Math.round(n * (UNIT[m[2].toLowerCase()] || 1)) : NaN;
};

const trimNum = (x: number): string => (Math.round(x * 100) / 100).toString();

/** Integer -> compact unit string for an input: 1_500_000 -> "1.5M". */
export const fmtUnit = (n: number): string => {
  n = +n || 0;
  return n >= 1e9
    ? trimNum(n / 1e9) + "G"
    : n >= 1e6
    ? trimNum(n / 1e6) + "M"
    : n >= 1e3
    ? trimNum(n / 1e3) + "k"
    : "" + n;
};

export const timeStr = (t: number): string => new Date(t * 1000).toLocaleTimeString();

// Scope palette: teal (calm) -> cyan -> amber (load) -> coral (alarm).
export const loadColor = (p: number): string =>
  p >= 100 ? "#ff5d6c" : p >= 80 ? "#f5b13d" : p >= 50 ? "#5fc9e0" : "#2fd4c4";

// Drop% escalates faster than load: teal <10%, amber by 33%, coral by 66%.
export const dropColor = (p: number): string =>
  p >= 66 ? "#ff5d6c" : p >= 33 ? "#f5b13d" : p >= 10 ? "#5fc9e0" : "#2fd4c4";
