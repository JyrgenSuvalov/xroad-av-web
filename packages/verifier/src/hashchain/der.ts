/**
 * DigestList DER encoding (DL:73-96):
 *
 *   DigestList   ::= SEQUENCE OF SingleDigest
 *   SingleDigest ::= SEQUENCE { digest OCTET STRING, algorithm UTF8String, transforms SEQUENCE {} }
 *
 *   encodeDigestList([{ algorithm, value }]) → DER bytes (not hashed)
 *
 * `algorithm` is the digest method URI exactly as resolved (Java
 * DigestAlgorithm.uri(), which for a URI lookup is the attribute string).
 */
import { encodeUtf8 } from '../util/bytes';

export interface DigestValue {
  algorithm: string;
  value: Uint8Array;
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  const len = content.length;
  let header: number[];
  if (len < 0x80) {
    header = [tag, len];
  } else {
    const lenBytes: number[] = [];
    for (let n = len; n > 0; n = Math.floor(n / 256)) lenBytes.unshift(n & 0xff);
    header = [tag, 0x80 | lenBytes.length, ...lenBytes];
  }
  const out = new Uint8Array(header.length + len);
  out.set(header, 0);
  out.set(content, header.length);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const SEQUENCE = 0x30;
const OCTET_STRING = 0x04;
const UTF8_STRING = 0x0c;

export function encodeDigestList(items: readonly DigestValue[]): Uint8Array {
  const singles = items.map((d) =>
    tlv(
      SEQUENCE,
      concat([tlv(OCTET_STRING, d.value), tlv(UTF8_STRING, encodeUtf8(d.algorithm)), tlv(SEQUENCE, new Uint8Array(0))]),
    ),
  );
  return tlv(SEQUENCE, concat(singles));
}
