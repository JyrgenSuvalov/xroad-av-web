// Byte-exact MIME splitting for the signed configuration directory.
// We search a latin1 view of the
// bytes but always report byte offsets, so callers slice the original buffer
// and never re-serialise.

import { latin1 } from '../util/bytes';
import { GlobalConfError } from './errors';

export type Headers = ReadonlyMap<string, string>;

export interface MimePart {
  /** Header names lowercased; values trimmed, case preserved (compared exactly). */
  headers: Headers;
  /** Byte offsets of the part body in the source buffer (end exclusive). */
  bodyStart: number;
  bodyEnd: number;
}

function malformed(msg: string): GlobalConfError {
  return new GlobalConfError('DIRECTORY_MALFORMED', msg);
}

/** Parse CRLF-separated header lines; folded continuation lines are joined. */
export function parseHeaderLines(text: string): Map<string, string> {
  const headers = new Map<string, string>();
  if (text === '') return headers;
  if (/(^|[^\r])\n/.test(text)) throw malformed('header block is not CRLF-terminated');
  const lines: string[] = [];
  for (const line of text.split('\r\n')) {
    if (/^[ \t]/.test(line) && lines.length > 0) lines[lines.length - 1] += ' ' + line.trim();
    else lines.push(line);
  }
  for (const line of lines) {
    if (line === '') continue;
    const i = line.indexOf(':');
    if (i <= 0) throw malformed(`invalid header line: ${JSON.stringify(line.slice(0, 80))}`);
    const name = line.slice(0, i).trim().toLowerCase();
    if (!headers.has(name)) headers.set(name, line.slice(i + 1).trim());
  }
  return headers;
}

/** Extract the `boundary` parameter of a multipart Content-Type value. */
export function boundaryOf(contentType: string, expectedType: string): string {
  if (!contentType.toLowerCase().startsWith(expectedType)) {
    throw malformed(`expected ${expectedType}, got ${JSON.stringify(contentType)}`);
  }
  const m = /;\s*boundary\s*=\s*(?:"([^"]*)"|([^;\s]+))/i.exec(contentType);
  const b = m?.[1] ?? m?.[2];
  if (!b) throw malformed('multipart boundary missing');
  return b;
}

/**
 * Split a full MIME entity (headers + body) at its first blank line.
 * Requires a CRLF-terminated header block.
 */
export function splitEntity(bytes: Uint8Array): { headers: Map<string, string>; bodyStart: number } {
  // Header blocks are small; avoid decoding the whole buffer.
  const head = latin1(bytes.subarray(0, Math.min(bytes.length, 64 * 1024)));
  const i = head.indexOf('\r\n\r\n');
  if (i < 0) throw malformed('no CRLF-terminated header block');
  return { headers: parseHeaderLines(head.slice(0, i)), bodyStart: i + 4 };
}

/**
 * Split a multipart body into parts (RFC 2046). `start`/`end` bound the body
 * in `bytes`. The CRLF before each `--boundary` belongs to the delimiter, so a
 * part's content ends right before it. Preamble and epilogue are ignored, as
 * mime4j does.
 */
export function splitMultipart(
  bytes: Uint8Array,
  boundary: string,
  start = 0,
  end = bytes.length,
): MimePart[] {
  const s = latin1(bytes.subarray(0, end));
  const dash = '--' + boundary;
  const delim = '\r\n' + dash;

  // First delimiter: at the very start of the body, or after a preamble line.
  let pos: number;
  if (s.startsWith(dash, start)) pos = start + dash.length;
  else {
    const j = s.indexOf(delim, start);
    if (j < 0) throw malformed('multipart: opening boundary not found');
    pos = j + delim.length;
  }

  const parts: MimePart[] = [];
  for (;;) {
    const after = s.slice(pos, pos + 2);
    if (after === '--') return parts; // close delimiter (epilogue ignored)
    if (after !== '\r\n') throw malformed('multipart: boundary not followed by CRLF');
    const contentStart = pos + 2;
    const next = s.indexOf(delim, contentStart);
    if (next < 0) throw malformed('multipart: close boundary not found (truncated?)');
    parts.push(splitPart(s, contentStart, next));
    pos = next + delim.length;
  }
}

/**
 * A part's content is `headers CRLF CRLF body`. The final CRLF of a
 * header-only part belongs to the next delimiter, which s[contentEnd..+2]
 * always holds, so search up to contentEnd + 2.
 */
function splitPart(s: string, contentStart: number, contentEnd: number): MimePart {
  if (s.startsWith('\r\n', contentStart)) {
    return { headers: new Map(), bodyStart: contentStart + 2, bodyEnd: contentEnd };
  }
  const i = s.indexOf('\r\n\r\n', contentStart);
  if (i < 0 || i + 2 > contentEnd) {
    throw malformed('multipart: part has no header terminator');
  }
  return {
    headers: parseHeaderLines(s.slice(contentStart, i)),
    bodyStart: Math.min(i + 4, contentEnd),
    bodyEnd: contentEnd,
  };
}
