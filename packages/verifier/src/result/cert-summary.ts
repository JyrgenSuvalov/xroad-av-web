/**
 * CertSummary in the reference harness's format:
 *   subject/issuer  X500Principal.getName(RFC2253)   → nameToRfc2253
 *   serialNumber    BigInteger.toString()            → decimal, '-' for negative DER ints
 *   notBefore/After yyyy-MM-dd'T'HH:mm:ss.SSS'Z'      → Date.toISOString()
 */
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { integerValue, parseStrict, timeValue } from '../trust/der';
import { issuerDer, subjectDer } from '../trust/x500';
import type { CertSummary } from '../types';
import { nameToRfc2253 } from './rfc2253';

export function certSummary(cert: pkijs.Certificate | Uint8Array): CertSummary {
  const c = cert instanceof Uint8Array ? pkijs.Certificate.fromBER(new Uint8Array(cert)) : cert;
  const [notBefore, notAfter] = validity(c);
  return {
    subject: nameToRfc2253(subjectDer(c)),
    issuer: nameToRfc2253(issuerDer(c)),
    serialNumber: integerValue(c.serialNumber).toString(),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  };
}

/**
 * Validity from the original TBS encoding, so GeneralizedTime fractions follow
 * java.util.Date (ms kept, finer truncated) like the rest of the port; falls back to
 * pkijs' decoded Time when the TBS bytes are unavailable.
 */
function validity(c: pkijs.Certificate): [Date, Date] {
  const fallback: [Date, Date] = [c.notBefore.value, c.notAfter.value];
  const tbs = c.tbsView.byteLength ? parseStrict(c.tbsView) : null;
  if (!(tbs instanceof asn1js.Sequence)) return fallback;
  const items = tbs.valueBlock.value;
  const hasVersion = items[0]?.idBlock.tagClass === 3 && items[0]?.idBlock.tagNumber === 0;
  const v = items[hasVersion ? 4 : 3];
  if (!(v instanceof asn1js.Sequence)) return fallback;
  const [nb, na] = v.valueBlock.value.map((el) => timeValue(el));
  return nb && na ? [nb, na] : fallback;
}
