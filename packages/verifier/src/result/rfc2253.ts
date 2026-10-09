/**
 * JDK `X500Principal.getName(X500Principal.RFC2253)` for a DER-encoded Name, byte-exact.
 * Confirmed against eclipse-temurin 21 by
 * test/result/rfc2253-vectors.json (expectations from a JDK probe).
 *
 * JDK behaviour reproduced (sun.security.x509 X500Name / RDN / AVA / AVAKeyword):
 *   - RDNs in reverse DER order, joined with ','; AVAs of a multi-valued RDN in DER
 *     (SET as encoded) order, joined with '+'.
 *   - Keywords only for CN C L ST O OU STREET DC UID; every other type as a dotted OID.
 *   - The value is `#<hex of its DER>` (tag + minimal length + contents) when the type is
 *     a dotted OID or the value is not one of Printable/T61/IA5/General/UTF8/BMPString.
 *   - Otherwise DerValue.getAsString(): UTF8 → UTF-8 (java.lang.String replacement
 *     semantics), Printable/IA5/General/T61 → ISO-8859-1 (probed: no ASCII check),
 *     BMP → UTF-16BE (JDK surrogate quirks, see decodeBmpJava); then escape `,=+<>#;"\` with '\', NUL as `\00`, and leading/trailing
 *     ' ' or '\r' with '\' (all other characters verbatim).
 */

import { toHex } from '../util/bytes';

const KEYWORDS: Readonly<Record<string, string>> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.9': 'STREET',
  '0.9.2342.19200300.100.1.25': 'DC',
  '0.9.2342.19200300.100.1.1': 'UID',
};

const TAG_UTF8 = 0x0c;
const TAG_PRINTABLE = 0x13;
const TAG_T61 = 0x14;
const TAG_IA5 = 0x16;
const TAG_GENERAL = 0x1b;
const TAG_BMP = 0x1e;

const ESCAPEES = ',=+<>#;"\\';

interface Tlv {
  /** Tag octets (possibly multi-byte). */
  tag: Uint8Array;
  /** Contents octets. */
  value: Uint8Array;
  /** Offset just past this element. */
  end: number;
}

function readTlv(buf: Uint8Array, off: number, limit: number): Tlv {
  const start = off;
  if (off >= limit) throw new Error('rfc2253: truncated DER');
  if ((buf[off++]! & 0x1f) === 0x1f) {
    while (off < limit && buf[off]! & 0x80) off++;
    off++;
  }
  const tag = buf.subarray(start, off);
  if (off >= limit) throw new Error('rfc2253: truncated DER');
  let len = buf[off++]!;
  if (len === 0x80) throw new Error('rfc2253: indefinite length');
  if (len > 0x80) {
    const n = len & 0x7f;
    if (n > 4 || off + n > limit) throw new Error('rfc2253: bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off++]!;
  }
  if (off + len > limit) throw new Error('rfc2253: truncated DER');
  return { tag, value: buf.subarray(off, off + len), end: off + len };
}

function children(t: Tlv, expectTag: number): Tlv[] {
  if (t.tag.length !== 1 || t.tag[0] !== expectTag) throw new Error(`rfc2253: expected tag 0x${expectTag.toString(16)}`);
  const out: Tlv[] = [];
  for (let off = 0; off < t.value.length; ) {
    const c = readTlv(t.value, off, t.value.length);
    out.push(c);
    off = c.end;
  }
  return out;
}

function oidString(t: Tlv): string {
  if (t.tag.length !== 1 || t.tag[0] !== 0x06 || t.value.length === 0) throw new Error('rfc2253: expected OID');
  const arcs: bigint[] = [];
  let v = 0n;
  for (const b of t.value) {
    v = (v << 7n) | BigInt(b & 0x7f);
    if (!(b & 0x80)) {
      arcs.push(v);
      v = 0n;
    }
  }
  const first = arcs[0]!;
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...head, ...arcs.slice(1)].join('.');
}

/** DerValue.toByteArray(): tag, minimal definite length, contents. */
function reencodedHex(t: Tlv): string {
  const n = t.value.length;
  const len: number[] = [];
  if (n < 0x80) len.push(n);
  else {
    for (let v = n; v > 0; v = Math.floor(v / 256)) len.unshift(v & 0xff);
    len.unshift(0x80 | len.length);
  }
  return toHex(t.tag) + toHex(Uint8Array.from(len)) + toHex(t.value);
}

const REPL = '�';

function decodeLatin1(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return s;
}

const isHigh = (c: number) => c >= 0xd800 && c <= 0xdbff;
const isLow = (c: number) => c >= 0xdc00 && c <= 0xdfff;

/**
 * BMPString as the JDK reads it (UTF-16BE, BOM kept): a high surrogate followed by a
 * non-low unit → one U+FFFD consuming both; a lone low surrogate or an odd/truncated
 * tail → U+FFFD. A valid surrogate pair makes X500Principal throw
 * IllegalArgumentException, so we throw too.
 */
function decodeBmpJava(b: Uint8Array): string {
  const out: number[] = [];
  let i = 0;
  while (i + 1 < b.length) {
    const c = (b[i]! << 8) | b[i + 1]!;
    if (isHigh(c)) {
      if (i + 3 >= b.length) {
        out.push(0xfffd);
        i = b.length;
        break;
      }
      if (isLow((b[i + 2]! << 8) | b[i + 3]!)) throw new Error('rfc2253: BMPString with a surrogate pair (rejected by the JDK)');
      out.push(0xfffd);
      i += 4;
    } else {
      out.push(isLow(c) ? 0xfffd : c);
      i += 2;
    }
  }
  if (i < b.length) out.push(0xfffd);
  return String.fromCharCode(...out);
}

const notCont = (b: number) => (b & 0xc0) !== 0x80;

/**
 * java.lang.String(bytes, UTF_8) (String.decodeUTF8_UTF16, doReplace): differs from the
 * WHATWG decoder in how many U+FFFD a malformed sequence yields (e.g. an encoded
 * surrogate ED A0 80 is a single U+FFFD) and in truncated tails.
 */
export function decodeUtf8Java(src: Uint8Array): string {
  const out: number[] = [];
  const sl = src.length;
  let sp = 0;
  while (sp < sl) {
    const b1 = src[sp++]!;
    if (b1 < 0x80) {
      out.push(b1);
    } else if ((b1 & 0xe0) === 0xc0 && (b1 & 0x1e) !== 0) {
      if (sp < sl) {
        const b2 = src[sp++]!;
        if (notCont(b2)) {
          out.push(0xfffd);
          sp--;
        } else {
          out.push(((b1 & 0x1f) << 6) | (b2 & 0x3f));
        }
        continue;
      }
      out.push(0xfffd);
      break;
    } else if ((b1 & 0xf0) === 0xe0) {
      if (sp + 1 < sl) {
        const b2 = src[sp++]!;
        const b3 = src[sp++]!;
        if ((b1 === 0xe0 && (b2 & 0xe0) === 0x80) || notCont(b2) || notCont(b3)) {
          out.push(0xfffd);
          sp -= 2; // back to b2; malformed3 consumed 1 (b1) or 2 (b1 b2)
          if (!((b1 === 0xe0 && (b2 & 0xe0) === 0x80) || notCont(b2))) sp++;
        } else {
          const c = ((b1 & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
          out.push(c >= 0xd800 && c <= 0xdfff ? 0xfffd : c);
        }
        continue;
      }
      if (sp < sl && ((b1 === 0xe0 && (src[sp]! & 0xe0) === 0x80) || notCont(src[sp]!))) {
        out.push(0xfffd);
        continue;
      }
      out.push(0xfffd);
      break;
    } else if ((b1 & 0xf8) === 0xf0) {
      if (sp + 2 < sl) {
        const b2 = src[sp++]!;
        const b3 = src[sp++]!;
        const b4 = src[sp++]!;
        const uc = ((b1 & 0x07) << 18) | ((b2 & 0x3f) << 12) | ((b3 & 0x3f) << 6) | (b4 & 0x3f);
        if (notCont(b2) || notCont(b3) || notCont(b4) || uc < 0x10000 || uc > 0x10ffff) {
          out.push(0xfffd);
          sp -= 3; // back to b2; malformed4 consumed 1, 2 or 3
          if (!(b1 > 0xf4 || (b1 === 0xf0 && (b2 < 0x90 || b2 > 0xbf)) || (b1 === 0xf4 && (b2 & 0xf0) !== 0x80) || notCont(b2))) {
            sp++;
            if (!notCont(b3)) sp++;
          }
        } else {
          out.push(uc);
        }
        continue;
      }
      if (b1 > 0xf4 || (sp < sl && isMalformed4_2(b1, src[sp]!))) {
        out.push(0xfffd);
        continue;
      }
      sp++;
      out.push(0xfffd);
      if (sp < sl && notCont(src[sp]!)) continue;
      break;
    } else {
      out.push(0xfffd);
    }
  }
  return String.fromCodePoint(...out);
}

function isMalformed4_2(b1: number, b2: number): boolean {
  return (b1 === 0xf0 && (b2 < 0x90 || b2 > 0xbf)) || (b1 === 0xf4 && (b2 & 0xf0) !== 0x80) || notCont(b2);
}

function decodeString(tag: number, v: Uint8Array): string | null {
  switch (tag) {
    case TAG_UTF8:
      return decodeUtf8Java(v);
    case TAG_PRINTABLE:
    case TAG_IA5:
    case TAG_GENERAL:
    case TAG_T61:
      return decodeLatin1(v);
    case TAG_BMP:
      return decodeBmpJava(v);
    default:
      return null;
  }
}

/** AVA.toRFC2253String. */
function avaToRfc2253(ava: Tlv): string {
  const [type, value, ...rest] = children(ava, 0x30);
  if (!type || !value || rest.length) throw new Error('rfc2253: malformed AttributeTypeAndValue');
  const oid = oidString(type);
  const keyword = KEYWORDS[oid] ?? oid;
  const str = /^[0-9]/.test(keyword) || value.tag.length !== 1 ? null : decodeString(value.tag[0]!, value.value);
  if (str === null) return `${keyword}=#${reencodedHex(value)}`;

  let escaped = '';
  for (const c of str) {
    if (ESCAPEES.includes(c)) escaped += '\\' + c;
    else if (c === '\u0000') escaped += '\\00';
    else escaped += c;
  }
  // Leading/trailing ' ' and '\r' (UTF-16 units of the escaped text) get a '\'.
  const chars = escaped;
  let lead = 0;
  while (lead < chars.length && (chars[lead] === ' ' || chars[lead] === '\r')) lead++;
  let trail = chars.length - 1;
  while (trail >= 0 && (chars[trail] === ' ' || chars[trail] === '\r')) trail--;
  let res = '';
  for (let i = 0; i < chars.length; i++) {
    if (i < lead || i > trail) res += '\\';
    res += chars[i];
  }
  return `${keyword}=${res}`;
}

/** X500Principal.getName(RFC2253) of a DER Name. Throws on DER it cannot walk. */
export function nameToRfc2253(der: Uint8Array): string {
  const name = readTlv(der, 0, der.length);
  if (name.end !== der.length) throw new Error('rfc2253: trailing data after Name');
  return children(name, 0x30)
    .map((rdn) => children(rdn, 0x31).map(avaToRfc2253).join('+'))
    .reverse()
    .join(',');
}
