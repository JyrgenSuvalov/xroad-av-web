/**
 * REST message parsing: port of RestMessage.of / RestRequest / RestResponse
 * (7.8.3, header/README.md).
 *
 *   parseRest(text) → RestParseResult   - throws RestError on any failure
 *     (Java: any exception → getSigner throws internal_error "Invalid message")
 *
 * `text` is the Java String of message.xml; Java re-encodes it as UTF-8 and
 * reads it back with a UTF-8 reader, which gives the same string.
 */
import { decodeBase64Lenient, decodeUtf8 } from '../util/bytes';
import {
  createClientId,
  createSecurityServerId,
  createServiceId,
  serviceClientId,
  type ClientId,
  type SecurityServerId,
  type ServiceId,
} from './ids';

export class RestError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'RestError';
  }
}

export const REST_VERBS = ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE'] as const;
export type RestVerb = (typeof REST_VERBS)[number];

/** RestMessage.SKIPPED_HEADERS (hop-by-hop etc.): such a header makes the message invalid. */
const SKIPPED_HEADERS = new Set([
  'transfer-encoding',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'upgrade',
  'connection',
  'user-agent',
  'host',
  'content-length',
  'server',
  'expect',
]);

export const H_QUERY_ID = 'x-road-id';
export const H_CLIENT_ID = 'x-road-client';
export const H_SERVICE_ID = 'x-road-service';
export const H_REQUEST_HASH = 'x-road-request-hash';
export const H_REQUEST_ID = 'x-road-request-id';
export const H_USER_ID = 'x-road-userid';
export const H_ISSUE = 'x-road-issue';
export const H_SECURITY_SERVER = 'x-road-security-server';
export const H_REPRESENTED_PARTY = 'x-road-represented-party';

export type RestHeader = readonly [name: string, value: string];

interface RestCommon {
  /** Headers in message order, name as written, value untrimmed. */
  headers: RestHeader[];
  /** Last x-road-id value (case-insensitive match). */
  queryId?: string;
  requestId?: string;
  /** x-road-userid / x-road-issue: display only (Java does not parse them). */
  userId?: string;
  issue?: string;
}

export interface RestRequestResult extends RestCommon {
  direction: 'request';
  verb: RestVerb;
  /** Raw path and query from line 2. */
  path: string;
  query: string | null;
  /** The service from the /r1/<inst>/<class>/<member>/<subsystem>/<service> path. */
  service: ServiceId;
  /** Path after the service code, '' if none (Java servicePath). */
  servicePath: string;
  /** Last X-Road-Client; null if absent → signer null. */
  client: ClientId | null;
  securityServer?: SecurityServerId;
  representedParty?: { partyClass: string | null; partyCode: string | null };
  /** RestRequest.getSender() */
  sender: ClientId | null;
}

export interface RestResponseResult extends RestCommon {
  direction: 'response';
  status: number;
  reason: string | null;
  /** The raw x-road-request-hash value (non-empty when decoded). */
  requestHash: string;
  service: ServiceId;
  client?: ClientId;
  /** RestResponse.getSender() = service.getClientId(). */
  sender: ClientId;
}

export type RestParseResult = RestRequestResult | RestResponseResult;

/** BufferedReader.readLine over a whole string (\n, \r, \r\n; no trailing empty line). */
export function javaReadLines(s: string): string[] {
  const lines: string[] = [];
  let start = 0;
  let i = 0;
  while (i < s.length) {
    const c = s.charCodeAt(i);
    if (c === 0x0a || c === 0x0d) {
      lines.push(s.slice(start, i));
      i += c === 0x0d && s.charCodeAt(i + 1) === 0x0a ? 2 : 1;
      start = i;
    } else {
      i++;
    }
  }
  if (start < s.length) lines.push(s.slice(start));
  return lines;
}

/** Java String.split(sep) for a single literal char, limit > 0 or 0 (trailing empties dropped). */
export function javaSplit(s: string, sep: string, limit = 0): string[] {
  const parts: string[] = [];
  let start = 0;
  for (;;) {
    if (limit > 0 && parts.length === limit - 1) break;
    const i = s.indexOf(sep, start);
    if (i < 0) break;
    parts.push(s.slice(start, i));
    start = i + sep.length;
  }
  parts.push(s.slice(start));
  if (limit === 0) {
    // "" alone stays [""]; otherwise trailing empty strings are removed.
    if (parts.length === 1) return parts;
    while (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
  }
  return parts;
}

const SAFE = /^[A-Za-z0-9\-._~!$&'()*+,;=:@]$/;
const HEX = /^[0-9A-Fa-f]{2}$/;

/** UriUtils.uriSegmentPercentDecode (strict). */
export function uriSegmentPercentDecode(src: string): string {
  if (src.length === 0) return src;
  const buf: number[] = [];
  let changed = false;
  for (let i = 0; i < src.length; ) {
    const ch = src[i]!;
    if (ch === '%') {
      if (i + 2 >= src.length) throw new RestError('Incomplete percent encoding');
      const hh = src.slice(i + 1, i + 3);
      if (!HEX.test(hh)) throw new RestError('Invalid percent encoding');
      buf.push(parseInt(hh, 16));
      i += 3;
      changed = true;
    } else if (SAFE.test(ch)) {
      buf.push(ch.charCodeAt(0));
      i++;
    } else {
      throw new RestError('Invalid character in path segment');
    }
  }
  return changed ? decodeUtf8(new Uint8Array(buf)) : src;
}

// java.net.URI (RFC 2396) character classes for the parts we need.
const UNRESERVED = "A-Za-z0-9\\-_.!~*'()";
const PATH_CHARS = new RegExp(`^[${UNRESERVED}:@&=+$,;/]$`);
const URIC_CHARS = new RegExp(`^[${UNRESERVED};/?:@&=+$,\\[\\]]$`);

/** Java URI "other" category: non-ASCII (> 128), not a space char, not ISO control. */
function isUriOther(c: number): boolean {
  return c > 128 && !/^[\p{Zs}\p{Zl}\p{Zp}\p{Cc}]$/u.test(String.fromCharCode(c));
}

function checkUriChars(s: string, allowed: RegExp, what: string): void {
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === '%') {
      if (!HEX.test(s.slice(i + 1, i + 3))) throw new RestError(`Malformed escape pair in ${what}`);
      i += 2;
    } else if (!allowed.test(ch) && !isUriOther(ch.charCodeAt(0))) {
      throw new RestError(`Illegal character in ${what}`);
    }
  }
}

/**
 * The subset of `new java.net.URI(s)` RestRequest relies on: rejects a scheme or
 * an authority and illegal characters; returns the raw path and raw query.
 * (Any ':' before the first '/', '?' or '#' is a scheme or a syntax error.)
 */
export function parseRequestUri(s: string): { rawPath: string; rawQuery: string | null } {
  let end = s.length;
  const hash = s.indexOf('#');
  if (hash >= 0) {
    checkUriChars(s.slice(hash + 1), URIC_CHARS, 'fragment');
    end = hash;
  }
  const firstDelim = s.search(/[/?#]/);
  const colon = s.indexOf(':');
  if (colon >= 0 && (firstDelim < 0 || colon < firstDelim)) throw new RestError('Invalid request URI');
  let p = 0;
  if (s.startsWith('//')) {
    const q = s.slice(2, end).search(/[/?]/);
    const qq = q < 0 ? end : q + 2;
    if (qq > 2) throw new RestError('Invalid request URI'); // authority present
    if (qq >= end) throw new RestError('Expected authority');
    p = qq; // empty authority before a path or query: allowed, authority stays null
  }
  const qm = s.indexOf('?', p);
  const pathEnd = qm >= 0 && qm < end ? qm : end;
  const rawPath = s.slice(p, pathEnd);
  checkUriChars(rawPath, PATH_CHARS, 'path');
  let rawQuery: string | null = null;
  if (pathEnd < end) {
    rawQuery = s.slice(pathEnd + 1, end);
    checkUriChars(rawQuery, URIC_CHARS, 'query');
  }
  return { rawPath, rawQuery };
}

/** RestMessage.split */
function splitHeader(line: string): RestHeader {
  if (line.length === 0) throw new RestError('Invalid header');
  const i = line.indexOf(':');
  if (i < 0) throw new RestError('Invalid header');
  const name = line.slice(0, i);
  if (SKIPPED_HEADERS.has(name.toLowerCase())) throw new RestError(`Invalid header: ${name}`);
  return [name, line.slice(i + 1)];
}

export function decodeClientId(value: string): ClientId {
  const p = javaSplit(value, '/', 5);
  if (p.length < 3 || p.length > 4) throw new RestError('Invalid Client Id');
  return createClientId(
    uriSegmentPercentDecode(p[0]!),
    uriSegmentPercentDecode(p[1]!),
    uriSegmentPercentDecode(p[2]!),
    p.length === 4 ? uriSegmentPercentDecode(p[3]!) : null,
  );
}

export function decodeServiceId(value: string): ServiceId {
  const p = javaSplit(value, '/', 6);
  if (p.length !== 5) throw new RestError('Invalid Service Id');
  const d = p.map(uriSegmentPercentDecode);
  return createServiceId(d[0], d[1], d[2], d[3], d[4], null);
}

function decodeServerId(value: string): SecurityServerId {
  const p = javaSplit(value, '/', 5);
  if (p.length !== 4) throw new RestError('Invalid SecurityServer Id');
  const d = p.map(uriSegmentPercentDecode);
  return createSecurityServerId(d[0], d[1], d[2], d[3]);
}

function decodeRepresentedParty(value: string): { partyClass: string | null; partyCode: string | null } | undefined {
  const p = javaSplit(value, '/');
  if (p.length > 2) throw new RestError('Invalid RepresentedParty Id');
  if (p.length === 1) return { partyClass: null, partyCode: uriSegmentPercentDecode(p[0]!) };
  if (p.length === 2) return { partyClass: uriSegmentPercentDecode(p[0]!), partyCode: uriSegmentPercentDecode(p[1]!) };
  return undefined;
}

const eqi = (a: string, b: string) => a.toLowerCase() === b;

function displayHeaders(headers: RestHeader[], into: RestCommon): void {
  for (const [n, v] of headers) {
    if (eqi(n, H_USER_ID)) into.userId = v;
    else if (eqi(n, H_ISSUE)) into.issue = v;
  }
}

function parseRequest(lines: string[]): RestRequestResult {
  const verbLine = lines[0]!;
  if (!(REST_VERBS as readonly string[]).includes(verbLine)) {
    throw new RestError(`No enum constant RestRequest.Verb.${verbLine}`);
  }
  const uriLine = lines[1];
  if (uriLine === undefined) throw new RestError('Request uri must not be null');
  const { rawPath, rawQuery } = parseRequestUri(uriLine);
  const headers = lines.slice(2).map(splitHeader);

  // decodeIdentifiers
  const parts = javaSplit(rawPath, '/', 8);
  if (parts.length < 7) throw new RestError('Invalid request URI');
  const v = parts[1]!;
  if (!(v.length === 2 && v[0] === 'r' && /^[0-9]$/.test(v[1]!))) throw new RestError(`Invalid protocol version ${v}`);
  if (v[1] !== '1') throw new RestError(`Unsupported protocol version ${v[1]}`);
  const d = parts.slice(2, 7).map(uriSegmentPercentDecode);
  const service = createServiceId(d[0], d[1], d[2], d[3], d[4], null);
  const servicePath = parts.length === 8 ? `/${parts[7]}` : '';

  const r: RestRequestResult = {
    direction: 'request',
    verb: verbLine as RestVerb,
    path: rawPath,
    query: rawQuery,
    service,
    servicePath,
    client: null,
    sender: null,
    headers,
  };
  // decodeHeaders
  for (const [n, val] of headers) {
    if (eqi(n, H_CLIENT_ID)) r.client = decodeClientId(val);
    else if (eqi(n, H_QUERY_ID)) r.queryId = val;
    else if (n === H_REQUEST_ID) r.requestId = val;
    else if (eqi(n, H_SECURITY_SERVER)) r.securityServer = decodeServerId(val);
    else if (eqi(n, H_REPRESENTED_PARTY)) r.representedParty = decodeRepresentedParty(val);
  }
  r.sender = r.client;
  displayHeaders(headers, r);
  return r;
}

/** Integer.parseInt(s, 10), ASCII digits only (Java also accepts other Unicode Nd digits). */
function parseJavaInt(s: string): number {
  if (!/^[+-]?[0-9]+$/.test(s)) throw new RestError(`For input string: "${s}"`);
  const n = Number(s);
  if (n > 2147483647 || n < -2147483648) throw new RestError(`For input string: "${s}"`);
  return n;
}

function parseResponse(lines: string[]): RestResponseResult {
  const status = parseJavaInt(lines[0]!);
  const reason = lines[1] ?? null;
  const headers = lines.slice(2).map(splitHeader);

  let queryId: string | undefined;
  let requestHash: string | undefined;
  let requestHashLen = 0;
  let service: ServiceId | undefined;
  let client: ClientId | undefined;
  let requestId: string | undefined;
  for (const [n, val] of headers) {
    if (eqi(n, H_QUERY_ID)) queryId = val;
    if (eqi(n, H_REQUEST_HASH)) {
      requestHash = val;
      requestHashLen = decodeBase64Lenient(val).length;
    }
    if (eqi(n, H_SERVICE_ID)) service = decodeServiceId(val);
    if (eqi(n, H_CLIENT_ID)) client = decodeClientId(val);
    if (eqi(n, H_REQUEST_ID)) requestId = val;
  }
  if (queryId == null || requestHash == null || queryId.length === 0 || requestHashLen === 0) {
    throw new RestError('Invalid REST Response message');
  }
  if (service == null) throw new RestError('x-road-service header missing (NPE in getSender)');
  const r: RestResponseResult = {
    direction: 'response',
    status,
    reason,
    requestHash,
    service,
    sender: serviceClientId(service),
    headers,
    queryId,
    ...(client ? { client } : {}),
    ...(requestId != null ? { requestId } : {}),
  };
  displayHeaders(headers, r);
  return r;
}

export function parseRest(text: string): RestParseResult {
  if (text.length === 0) throw new RestError('Invalid message');
  const lines = javaReadLines(text);
  const first = text.charCodeAt(0);
  return first >= 0x31 && first <= 0x39 ? parseResponse(lines) : parseRequest(lines);
}
