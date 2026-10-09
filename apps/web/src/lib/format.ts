// Display formatting. Times are shown in UTC (as the jar prints them) plus local time.

function toDate(d: Date | string): Date {
  return typeof d === 'string' ? new Date(d) : d;
}

/** `2026-09-20 20:10:38 UTC`, or the input unchanged if it is not a date. */
export function fmtUtc(d: Date | string): string {
  const date = toDate(d);
  if (Number.isNaN(date.getTime())) return String(d);
  return date.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC').replace(/Z$/, ' UTC');
}

const timeFmt = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

const clockFmt = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  timeZoneName: 'short',
});

/** Local wall-clock time with zone, e.g. `14:42:29 GMT+2`. */
export function fmtClock(d: Date): string {
  return clockFmt.format(d);
}

export function fmtTime(d: Date): string {
  return timeFmt.format(d);
}

/** Human duration between two instants: `in 4 min 12 s`, `3 min ago`, `just now`. */
export function fmtRelative(target: Date, now: Date): string {
  const diff = Math.round((target.getTime() - now.getTime()) / 1000);
  const abs = Math.abs(diff);
  if (abs < 2) return 'just now';
  let text: string;
  if (abs < 60) text = `${abs} s`;
  else if (abs < 3600) text = `${Math.floor(abs / 60)} min ${abs % 60} s`;
  else if (abs < 86400) text = `${Math.floor(abs / 3600)} h ${Math.floor((abs % 3600) / 60)} min`;
  else text = `${Math.floor(abs / 86400)} d`;
  return diff > 0 ? `in ${text}` : `${text} ago`;
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

/** Group a long hex digest into 8-char blocks for legibility (copying still works, spaces aside). */
export function groupHex(hex: string): string {
  return hex.replace(/(.{8})(?=.)/g, '$1 ');
}

/** CN from an RFC 2253 DN, for card titles; falls back to the whole DN. */
export function commonName(dn: string): string {
  const m = /(?:^|,)\s*CN=((?:\\.|[^,\\])*)/.exec(dn);
  return m?.[1]?.replace(/\\(.)/g, '$1') ?? dn;
}

/** Safe download file name for an attachment entry name (untrusted). */
export function safeFileName(name: string): string {
  const cleaned = name.replace(/^.*[\\/]/, '').replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '');
  return (cleaned || 'attachment').slice(0, 100);
}
