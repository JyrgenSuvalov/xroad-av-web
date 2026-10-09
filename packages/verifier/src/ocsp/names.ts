/**
 * JDK X500Principal semantics needed by the OCSP / cert-path code.
 *
 *   jdkX500Equal(aDer, bDer)  - X500Principal.equals: byte-identical, or the
 *                               RFC 2253 canonical forms are equal. ORDER-SENSITIVE
 *                               over RDNs (unlike BC x500Equal); AVAs within an RDN
 *                               are compared as a set; string values are trimmed,
 *                               internal whitespace collapsed, Unicode case-folded
 *                               (toUpperCase().toLowerCase()) and NFKD-normalised;
 *                               non-string values compare as hex DER.
 *                               Used only for isAuthorizedOcspSigner step 3
 *                               (BC rules, see src/trust/x500.ts).
 *   jdkRfc2253(nameDer)       - X500Principal.getName() (RFC 2253): RDNs in reverse
 *                               DER order; keywords CN C L ST O OU STREET DC UID,
 *                               any other type as `<oid>=#<hex DER>`; RFC 2253
 *                               escaping. Fault strings only ("Unable to find OCSP
 *                               response for certificate …"); src/result owns the
 *                               CertSummary formatter (src/result).
 *
 * UNCONFIRMED approximation: which ASN.1 string types the JDK treats as strings
 * (we use the BC set from src/trust/x500.ts). Names in real containers are all
 * PrintableString/UTF8String and compared DER-identical.
 */
import * as asn1js from 'asn1js';
import { bytesEqual, toHex } from '../util/bytes';
import { elementDer } from '../trust/der';
import { asn1StringValue } from '../trust/x500';

const KEYWORDS: Record<string, string> = {
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

interface RawAva {
  oid: string;
  value: asn1js.AsnType;
}

function parseName(der: Uint8Array): RawAva[][] | null {
  const parsed = asn1js.fromBER(der);
  if (parsed.offset === -1 || parsed.offset !== der.length || !(parsed.result instanceof asn1js.Sequence)) return null;
  const out: RawAva[][] = [];
  for (const set of parsed.result.valueBlock.value) {
    if (!(set instanceof asn1js.Set)) return null;
    const rdn: RawAva[] = [];
    for (const atv of set.valueBlock.value) {
      if (!(atv instanceof asn1js.Sequence) || atv.valueBlock.value.length !== 2) return null;
      const [type, value] = atv.valueBlock.value as [asn1js.AsnType, asn1js.AsnType];
      if (!(type instanceof asn1js.ObjectIdentifier)) return null;
      rdn.push({ oid: type.valueBlock.toString(), value });
    }
    out.push(rdn);
  }
  return out;
}

function canonicalValue(value: asn1js.AsnType): string {
  const s = asn1StringValue(value);
  if (s === null || s.startsWith('#')) return '#' + toHex(elementDer(value));
  return s.trim().replace(/\s+/g, ' ').toUpperCase().toLowerCase().normalize('NFKD');
}

export function jdkX500Equal(a: Uint8Array, b: Uint8Array): boolean {
  if (bytesEqual(a, b)) return true;
  const ra = parseName(a);
  const rb = parseName(b);
  if (!ra || !rb || ra.length !== rb.length) return false;
  const canon = (rdn: RawAva[]) => rdn.map((x) => `${x.oid}=${canonicalValue(x.value)}`).sort();
  return ra.every((rdn, i) => {
    const x = canon(rdn);
    const y = canon(rb[i]!);
    return x.length === y.length && x.every((v, j) => v === y[j]);
  });
}

function escape(s: string): string {
  let out = s.replace(/[,+"\\<>;]/g, (c) => '\\' + c);
  if (out.startsWith('#') || out.startsWith(' ')) out = '\\' + out;
  if (out.length > 1 && out.endsWith(' ') && !out.endsWith('\\ ')) out = out.slice(0, -1) + '\\ ';
  return out;
}

export function jdkRfc2253(nameDer: Uint8Array): string {
  const rdns = parseName(nameDer);
  if (!rdns) return '';
  return [...rdns]
    .reverse()
    .map((rdn) =>
      rdn
        .map(({ oid, value }) => {
          const kw = KEYWORDS[oid];
          const str = kw ? asn1StringValue(value) : null;
          return str !== null ? `${kw}=${escape(str)}` : `${kw ?? oid}=#${toHex(elementDer(value))}`;
        })
        .join('+'),
    )
    .join(',');
}
