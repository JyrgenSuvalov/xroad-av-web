/**
 * Small DER/asn1js helpers shared by src/trust and src/timestamp (and src/ocsp).
 *
 *   elementDer(el)            - original encoding of a parsed asn1js element
 *   primitiveBytes(el)        - contents octets of a primitive element
 *   octetStringBytes(os)      - OCTET STRING contents, BER-constructed segments concatenated
 *   parseStrict(bytes)        - asn1js.fromBER that must consume all input; null otherwise
 *   integerValue(int)         - INTEGER as bigint (BigInteger value semantics)
 *   timeValue(el)             - UTCTime/GeneralizedTime → Date (ms precision, finer truncated)
 */

import * as asn1js from 'asn1js';

export function elementDer(el: asn1js.AsnType): Uint8Array {
  const raw = el.valueBeforeDecodeView;
  return raw && raw.byteLength > 0 ? new Uint8Array(raw) : new Uint8Array(el.toBER(false));
}

export function primitiveBytes(el: asn1js.AsnType): Uint8Array {
  const vb = el.valueBlock as unknown as { valueHexView?: Uint8Array };
  return new Uint8Array(vb.valueHexView ?? new Uint8Array(0));
}

export function octetStringBytes(os: asn1js.OctetString): Uint8Array {
  if (!os.idBlock.isConstructed) return primitiveBytes(os);
  const parts = os.valueBlock.value.map((p) => octetStringBytes(p as asn1js.OctetString));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Parse exactly one BER element covering all of `bytes`; null on any decode error or trailing data. */
export function parseStrict(bytes: Uint8Array): asn1js.AsnType | null {
  if (bytes.length === 0) return null;
  const parsed = asn1js.fromBER(bytes);
  if (parsed.offset === -1 || parsed.offset !== bytes.length || parsed.result.error) return null;
  if (hasError(parsed.result)) return null;
  return parsed.result;
}

function hasError(el: asn1js.AsnType): boolean {
  if (el.error) return true;
  const vb = el.valueBlock as unknown as { error?: string; value?: unknown };
  if (vb.error) return true;
  if (el.idBlock.isConstructed && Array.isArray(vb.value)) {
    return (vb.value as asn1js.AsnType[]).some(hasError);
  }
  return false;
}

export function integerValue(int: asn1js.Integer): bigint {
  return int.toBigInt();
}

/** UTCTime (YY < 50 → 20YY, as BC/JDK) or GeneralizedTime → Date; sub-millisecond digits truncated. */
export function timeValue(el: asn1js.AsnType): Date | null {
  if (el instanceof asn1js.GeneralizedTime) return generalizedTime(el);
  if (el instanceof asn1js.UTCTime) return el.toDate();
  return null;
}

/**
 * GeneralizedTime → Date with java.util.Date semantics: milliseconds kept,
 * finer fractions truncated (probed against BC 1.84, test/timestamp/probe).
 * Supports `YYYYMMDDHHMMSS[.f+]Z` and the +hhmm/-hhmm offset form.
 */
export function generalizedTime(el: asn1js.GeneralizedTime): Date | null {
  const raw = String.fromCharCode(...primitiveBytes(el));
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(?:[.,](\d+))?(Z|[+-]\d{4})?$/.exec(raw);
  if (!m) return null;
  const [, y, mo, d, h, mi = '0', s = '0', frac = '', tz = ''] = m;
  const ms = Number((frac + '000').slice(0, 3));
  let t = Date.UTC(+y!, +mo! - 1, +d!, +h!, +mi, +s, ms);
  if (tz && tz !== 'Z') {
    const sign = tz[0] === '+' ? 1 : -1;
    t -= sign * (Number(tz.slice(1, 3)) * 60 + Number(tz.slice(3, 5))) * 60_000;
  } else if (!tz) {
    return null; // local time without zone: not produced by TSAs; refuse rather than guess
  }
  const date = new Date(t);
  return Number.isNaN(date.getTime()) ? null : date;
}
