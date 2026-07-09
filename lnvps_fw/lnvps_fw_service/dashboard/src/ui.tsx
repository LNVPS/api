import type { ComponentChildren } from "preact";
import { useState } from "preact/hooks";
import { loadColor } from "./format";

export function LoadBar({ pct, color }: { pct: number; color?: (p: number) => string }) {
  const p = Math.min(pct, 100);
  const c = (color || loadColor)(pct);
  return (
    <span class="barwrap">
      <span class="bar"><span class="fill" style={{ width: p + "%", background: c }} /></span>
      <span style={{ color: c, fontWeight: 600 }}>{pct}%</span>
    </span>
  );
}

// Inline trend line over a rolling history buffer. `max` fixes the scale (e.g.
// 100 for a percentage); otherwise it auto-scales so the trend is always shown.
export function Sparkline({ data, color, max, w = 68, h = 22 }: {
  data: number[]; color: string; max?: number; w?: number; h?: number;
}) {
  if (!data || data.length < 2) return <svg class="spark" width={w} height={h} />;
  const m = max || Math.max(...data, 1);
  const n = data.length;
  const pts = data
    .map((v, i) => `${((i / (n - 1)) * w).toFixed(1)},${(h - 1 - Math.min(1, v / m) * (h - 2)).toFixed(1)}`)
    .join(" ");
  return (
    <svg class="spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} stroke-width="1.5"
        vector-effect="non-scaling-stroke" stroke-linejoin="round" />
    </svg>
  );
}

export type Cell = ComponentChildren;

export function Table({ cols, rows }: { cols: Cell[]; rows: Cell[][] }) {
  if (!rows.length) return <div class="muted">none</div>;
  return (
    <table>
      <thead><tr>{cols.map((c, i) => <th key={i}>{c}</th>)}</tr></thead>
      <tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j}>{c}</td>)}</tr>)}</tbody>
    </table>
  );
}

export function Pager({ page, pages, total, onPage }: {
  page: number; pages: number; total: number; onPage: (p: number) => void;
}) {
  return (
    <div class="pager">
      <button class="ghost" disabled={page <= 0} onClick={() => onPage(page - 1)}>‹ prev</button>
      <span class="muted">page {page + 1}/{pages} · {total} rows</span>
      <button class="ghost" disabled={page >= pages - 1} onClick={() => onPage(page + 1)}>next ›</button>
    </div>
  );
}

// Client-side paginated table (for bounded datasets).
export function PagedTable({ cols, rows, pageSize = 50 }: {
  cols: Cell[]; rows: Cell[][]; pageSize?: number;
}) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const p = Math.min(page, pages - 1);
  const slice = rows.slice(p * pageSize, p * pageSize + pageSize);
  return (
    <>
      <div class="scroll"><Table cols={cols} rows={slice} /></div>
      {rows.length > pageSize && <Pager page={p} pages={pages} total={rows.length} onPage={setPage} />}
    </>
  );
}

export function Section({ title, extra, wide, children }: {
  title: ComponentChildren; extra?: ComponentChildren; wide?: boolean; children: ComponentChildren;
}) {
  return (
    <section class={wide ? "wide" : ""}>
      <h2>{title}{extra ? <span class="muted">{extra}</span> : null}</h2>
      {children}
    </section>
  );
}

// Backdrop-dismissable modal.
export function Modal({ title, onClose, children }: {
  title: string; onClose: () => void; children: ComponentChildren;
}) {
  return (
    <div class="modal-bg" onClick={(e) => (e.target as HTMLElement).className === "modal-bg" && onClose()}>
      <div class="modal"><h3>{title}</h3>{children}</div>
    </div>
  );
}

export const flagCell = (f: number) => {
  const FLAGS: [number, string][] = [[1, "PORT_FILTER"], [2, "SYN_PROXY"], [4, "RATE_CAPS"], [8, "SOURCE_BLOCK"]];
  const o = FLAGS.filter(([b]) => f & b).map(([, n]) => n);
  return <span class="flag">{o.length ? o.join("|") : "none"}</span>;
};
