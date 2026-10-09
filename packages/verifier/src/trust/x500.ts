/**
 * X.500 Name equality with BouncyCastle 1.84 `X500Name.equals` semantics
 * (BCStyle / AbstractX500NameStyle / IETFUtils).
 *
 *   x500Equal(aDer, bDer)  - BC X500Name.equals over two DER-encoded Names
 *   nameDer(rdns)          - DER bytes of a pkijs RelativeDistinguishedNames
 *   issuerDer(cert) / subjectDer(cert) - the Name DER of a pkijs Certificate
 *
 * Used on the asic path for the TSA SignerId match, getCaCert (issuer →
 * CA subject) and OCSP responderID byName. NOT for isAuthorizedOcspSigner
 * step 3, which uses JDK X500Principal rules (order-sensitive, Unicode case).
 *
 * BC rules, in short:
 *   - byte-identical DER → equal;
 *   - otherwise same RDN count, each RDN of `a` matched against any unused RDN
 *     of `b` (order-insensitive; searched backwards when the first RDNs'
 *     first attribute types differ);
 *   - RDNs are equal when they have the same number of AVAs and the AVAs are
 *     pairwise equal by position: same OID and equal IETFUtils.canonicalString
 *     (string value regardless of string type, ASCII-only lowercase, escaped
 *     leading/trailing spaces trimmed, internal space runs collapsed; non-string
 *     values compare as '#' + hex DER);
 *   - anything that does not parse as a Name → not equal.
 */

import * as asn1js from 'asn1js';
import type * as pkijs from 'pkijs';
import { bytesEqual, decodeUtf8, toHex } from '../util/bytes';
import { elementDer, primitiveBytes } from './der';

interface Ava {
  oid: string;
  value: string; // IETFUtils.canonicalString
}
type Rdn = Ava[];

export function x500Equal(a: Uint8Array, b: Uint8Array): boolean {
  if (bytesEqual(a, b)) return true;
  const ra = parseName(a);
  const rb = parseName(b);
  if (!ra || !rb) return false;
  return bcAreEqual(ra, rb);
}

export function nameDer(rdns: pkijs.RelativeDistinguishedNames): Uint8Array {
  const raw = rdns.valueBeforeDecode;
  if (raw && raw.byteLength > 0) return new Uint8Array(raw);
  return new Uint8Array(rdns.toSchema().toBER(false));
}

export function issuerDer(cert: pkijs.Certificate): Uint8Array {
  return nameDer(cert.issuer);
}

export function subjectDer(cert: pkijs.Certificate): Uint8Array {
  return nameDer(cert.subject);
}

/** AbstractX500NameStyle.areEqual. */
function bcAreEqual(rdns1: Rdn[], rdns2In: Rdn[]): boolean {
  if (rdns1.length !== rdns2In.length) return false;
  if (rdns1.length === 0) return true;
  const rdns2: (Rdn | null)[] = [...rdns2In];
  const f1 = rdns1[0]![0];
  const f2 = rdns2In[0]![0];
  const reverse = f1 !== undefined && f2 !== undefined && f1.oid !== f2.oid;
  for (const rdn of rdns1) {
    if (!foundMatch(reverse, rdn, rdns2)) return false;
  }
  return true;
}

function foundMatch(reverse: boolean, rdn: Rdn, poss: (Rdn | null)[]): boolean {
  const order = reverse ? [...poss.keys()].reverse() : [...poss.keys()];
  for (const i of order) {
    const p = poss[i];
    if (p && rdnAreEqual(rdn, p)) {
      poss[i] = null;
      return true;
    }
  }
  return false;
}

function rdnAreEqual(a: Rdn, b: Rdn): boolean {
  if (a.length !== b.length) return false;
  return a.every((ava, i) => ava.oid === b[i]!.oid && ava.value === b[i]!.value);
}

/** Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value ANY }. null if not a Name. */
function parseName(der: Uint8Array): Rdn[] | null {
  const parsed = asn1js.fromBER(der);
  if (parsed.offset === -1 || parsed.offset !== der.length) return null;
  const seq = parsed.result;
  if (!(seq instanceof asn1js.Sequence)) return null;
  const rdns: Rdn[] = [];
  for (const set of seq.valueBlock.value) {
    if (!(set instanceof asn1js.Set)) return null;
    const rdn: Rdn = [];
    for (const atv of set.valueBlock.value) {
      if (!(atv instanceof asn1js.Sequence) || atv.valueBlock.value.length !== 2) return null;
      const [type, value] = atv.valueBlock.value as [asn1js.AsnType, asn1js.AsnType];
      if (!(type instanceof asn1js.ObjectIdentifier)) return null;
      rdn.push({ oid: type.valueBlock.toString(), value: canonicalString(value) });
    }
    rdns.push(rdn);
  }
  return rdns;
}

// ---------------------------------------------------------------------------
// IETFUtils.canonicalString(value) = canonicalize(valueToString(value))

/** Universal tags of BC ASN1String implementations (UniversalString handled as non-string). */
const LATIN1_STRING_TAGS = new Set([18, 19, 20, 21, 22, 25, 26, 27]); // Numeric..General
const TAG_UTF8 = 12;
const TAG_BMP = 30;
const TAG_BIT_STRING = 3;


const encoded = elementDer;

/** ASN1String.getString() for string-typed values; null for non-strings (and UniversalString). */
function asn1String(el: asn1js.AsnType): string | null {
  const id = el.idBlock;
  if (id.tagClass !== 1) return null;
  if (id.tagNumber === TAG_BIT_STRING) return '#' + toHex(encoded(el));
  const isString = id.tagNumber === TAG_UTF8 || id.tagNumber === TAG_BMP || LATIN1_STRING_TAGS.has(id.tagNumber);
  if (!isString) return null;
  if (id.isConstructed) return null; // BER constructed string: not produced by real CAs; compare as hex
  const bytes = primitiveBytes(el);
  if (id.tagNumber === TAG_UTF8) return decodeUtf8(bytes);
  if (id.tagNumber === TAG_BMP) {
    let s = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i]! << 8) | bytes[i + 1]!);
    return s;
  }
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

function valueToString(el: asn1js.AsnType): string {
  const str = asn1String(el);
  let v: string;
  if (str !== null && el.idBlock.tagNumber !== 28) {
    v = (str.length > 0 && str[0] === '#' ? '\\' : '') + str;
  } else {
    v = '#' + toHex(encoded(el));
  }
  const chars = [...v];
  let index = chars.length >= 2 && chars[0] === '\\' && chars[1] === '#' ? 2 : 0;
  while (index < chars.length) {
    if (',"\\+=<>;'.includes(chars[index]!)) {
      chars.splice(index, 0, '\\');
      index += 2;
    } else {
      index++;
    }
  }
  let start = 0;
  while (chars.length > start && chars[start] === ' ') {
    chars.splice(start, 0, '\\');
    start += 2;
  }
  let end = chars.length - 1;
  while (end >= 0 && chars[end] === ' ') {
    chars.splice(end, 0, '\\');
    end--;
  }
  return chars.join('');
}

/** Strings.toLowerCase: ASCII only. */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

function canonicalize(input: string): string {
  let s = input;
  if (s.length > 0 && s[0] === '#') {
    const decoded = decodeHexObject(s.slice(1));
    if (decoded !== null) s = decoded;
  }
  s = asciiLower(s);
  const length = s.length;
  if (length < 2) return s;
  let start = 0;
  const last = length - 1;
  while (start < last && s[start] === '\\' && s[start + 1] === ' ') start += 2;
  let end = last;
  const limit = start + 1;
  while (end > limit && s[end - 1] === '\\' && s[end] === ' ') end -= 2;
  if (start > 0 || end < last) s = s.substring(start, end + 1);
  return stripInternalSpaces(s);
}

/** IETFUtils.decodeObject + `instanceof ASN1String ? getString()`; null when not a string. */
function decodeHexObject(h: string): string | null {
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) return null;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  const parsed = asn1js.fromBER(bytes);
  if (parsed.offset === -1) return null;
  return asn1String(parsed.result);
}

function stripInternalSpaces(str: string): string {
  if (!str.includes('  ')) return str;
  let res = str[0]!;
  let c1 = str[0]!;
  for (let k = 1; k < str.length; k++) {
    const c2 = str[k]!;
    if (!(c1 === ' ' && c2 === ' ')) res += c2;
    c1 = c2;
  }
  return res;
}

/**
 * IETFUtils.valueToString: the RFC 2253-escaped string of an AttributeValue
 * (non-strings as '#' + hex DER). Used by CertUtils.getRDNValue (src/binding).
 */
export function rdnValueToString(el: asn1js.AsnType): string {
  return valueToString(el);
}

/** ASN1String.getString() for string-typed AttributeValues; null for non-strings. */
export function asn1StringValue(el: asn1js.AsnType): string | null {
  return asn1String(el);
}

/** Exposed for tests. */
export const _internal = { canonicalString: (el: asn1js.AsnType) => canonicalize(valueToString(el)) };

function canonicalString(el: asn1js.AsnType): string {
  return canonicalize(valueToString(el));
}
