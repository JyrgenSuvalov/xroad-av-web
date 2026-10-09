/**
 * Byte/string helpers with Java-compatible semantics.
 *
 *   decodeUtf8(bytes)      - lenient UTF-8 decode (U+FFFD), BOM kept (Java new String(b, UTF_8))
 *   encodeUtf8(str)        - String.getBytes(UTF_8)
 *   utf8RoundTrip(bytes)   - encodeUtf8(decodeUtf8(bytes))
 *   isJavaBlank(str)       - commons-lang3 StringUtils.isBlank
 *   decodeBase64Lenient(s) - DatatypeConverter.parseBase64Binary (skips non-alphabet chars)
 *   decodeBase64Strict(s)  - whitespace-tolerant but otherwise strict; null on bad input (globalconf)
 *   latin1(bytes)          - byte-preserving decode (each byte → one UTF-16 code unit)
 *   bytesEqual(a, b)       - constant-shape byte comparison
 *   arrayBufferCopy(bytes) - copy into a fresh ArrayBuffer-backed view (WebCrypto BufferSource)
 *   encodeBase64(bytes), toHex(bytes), sha512(bytes), crc32(bytes)
 *
 * Base64 has several decoders on purpose; they differ on invalid input and
 * each mirrors the Java decoder at its call site:
 *   decodeBase64Lenient - message/container/OCSP/header (JAXB DatatypeConverter)
 *   decodeBase64Strict  - globalconf anchor/directory/shared-params (reject garbage → null)
 *   xades/base64.ts decodeDsBase64 - Santuario XMLUtils.decode (java.util.Base64 MIME decoder,
 *                         throws IllegalArgumentException on bad padding)
 *   hashchain/parse.ts readDigestValue - xs:base64Binary schema validation, then atob
 */

const utf8Decoder = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true });
const utf8Encoder = new TextEncoder();

export function decodeUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

export function encodeUtf8(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

export function utf8RoundTrip(bytes: Uint8Array): Uint8Array {
  return encodeUtf8(decodeUtf8(bytes));
}

/** Java Character.isWhitespace for a UTF-16 code unit. */
export function isJavaWhitespace(c: number): boolean {
  if ((c >= 0x09 && c <= 0x0d) || (c >= 0x1c && c <= 0x20)) return true;
  if (c === 0x1680 || (c >= 0x2000 && c <= 0x2006) || (c >= 0x2008 && c <= 0x200a)) return true;
  return c === 0x2028 || c === 0x2029 || c === 0x205f || c === 0x3000;
}

export function isJavaBlank(s: string | null | undefined): boolean {
  if (s == null) return true;
  for (let i = 0; i < s.length; i++) if (!isJavaWhitespace(s.charCodeAt(i))) return false;
  return true;
}

export function decodeBase64Lenient(s: string): Uint8Array {
  let clean = s.replace(/[^A-Za-z0-9+/]/g, '');
  clean = clean.slice(0, clean.length - (clean.length % 4 === 1 ? 1 : 0));
  const bin = atob(clean + '='.repeat((4 - (clean.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64.length; i++) t[B64.charCodeAt(i)] = i;
  return t;
})();

/**
 * Strict base64 decode (globalconf): all whitespace is ignored, trailing '='
 * is stripped. Returns null on any other invalid character or impossible
 * length (unlike decodeBase64Lenient, which skips such characters).
 */
export function decodeBase64Strict(text: string): Uint8Array | null {
  const s = text.replace(/\s+/g, '').replace(/=+$/, '');
  if (s.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64_LOOKUP[c]! : -1;
    if (v < 0) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

export function encodeBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** Byte-preserving decode (each byte → one UTF-16 code unit), e.g. for MIME boundary search. */
export function latin1(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return s;
}

/** Constant-shape byte comparison (no early exit on the first difference). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** Copy into a fresh ArrayBuffer-backed view (WebCrypto wants BufferSource without SharedArrayBuffer). */
export function arrayBufferCopy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes.length);
  out.set(bytes);
  return out;
}

export async function sha512(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-512', bytes as BufferSource));
}

let crcTable: Uint32Array | undefined;

export function crc32(bytes: Uint8Array): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (const b of bytes) crc = crcTable[(crc ^ b) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
