/**
 * TrustQueries: the GlobalConfImpl-like helpers the verifier core uses on top
 * of a TrustContext (GlobalConfImpl 7.8.3 and
 * SharedParametersCache).
 *
 *   const q = trustQueries(trust);
 *   q.tspCertificates(now)                  - getTspCertificates
 *   q.getCaCert(instance, cert, now)        - getCaCert (BC X500Name issuer lookup)
 *   q.ocspResponderCertificates(now)        - getOcspResponderCertificates
 *   q.allCaCerts(now)                       - getAllCaCerts
 *   q.isOcspResponderCert(ca, ocsp, now)    - isOcspResponderCert
 *   q.ocspFreshnessSeconds()                - getOcspFreshnessSeconds (main instance)
 *   q.subjectName(...)                      - stub; see src/binding (profile decoders)
 *
 * `now` is wall-clock time and only drives TrustContext.visibleInstances
 * (non-main expiry filter). It is never the timestamp's atDate.
 *
 * HashMap semantics reproduced from SharedParametersCache:
 *   - subjectsAndCaCerts: Map<X500Name, cert>, filled in document order over
 *     every top/intermediate CA → for CAs whose subjects are BC-equal, the LAST
 *     one wins (getCaCert, getAllCaCerts dedupe by subject).
 *   - caCertsAndOcspData: Map<X509Certificate (DER), ocsp list> → for a CA cert
 *     listed twice, the LAST entry's OCSP list wins.
 * Java iterates those HashMaps in hash order (UNCONFIRMED, irrelevant with
 * unique entries); we iterate in first-insertion (document) order.
 */

import { CodedError, ErrorCodes } from '../util/errors';
import type { ApprovedCa, InstanceTrust, TrustContext, TrustedCert } from '../types';
import { bytesEqual } from '../util/bytes';
import { issuerDer, x500Equal } from './x500';

export interface TrustQueries {
  readonly trust: TrustContext;
  /** Main instance's globalSettings/ocspFreshnessSeconds. */
  ocspFreshnessSeconds(): number;
  /** approvedTSA certs of all visible instances, instance order then document order. */
  tspCertificates(now: Date): TrustedCert[];
  /**
   * The CA in `instance` whose subject BC-equals `cert`'s issuer (top or
   * intermediate; last one wins on duplicates). Throws internal_error if the
   * instance is not visible or no CA matches.
   */
  getCaCert(instance: string, cert: TrustedCert, now: Date): ApprovedCa;
  /** OCSP responder certs configured under any CA (CA cert deduped by DER, last wins). */
  ocspResponderCertificates(now: Date): TrustedCert[];
  /** Every visible top/intermediate CA cert, deduped by BC-equal subject per instance (last wins). */
  allCaCerts(now: Date): TrustedCert[];
  /** True if `ocspCert` (DER-equal) is configured under exactly the CA cert `ca` (DER-equal) in any visible instance. */
  isOcspResponderCert(ca: TrustedCert, ocspCert: TrustedCert, now: Date): boolean;
  /** Decode the signer ClientId from the cert via the CA's certificate profile. */
  subjectName(caProfile: string, signerInstance: string, cert: TrustedCert): never;
}

export function trustQueries(trust: TrustContext): TrustQueries {
  return {
    trust,
    ocspFreshnessSeconds: () => ocspFreshnessSeconds(trust),
    tspCertificates: (now) => trust.visibleInstances(now).flatMap((i) => i.tsaCerts),
    getCaCert: (instance, cert, now) => getCaCert(trust, instance, cert, now),
    ocspResponderCertificates: (now) =>
      trust.visibleInstances(now).flatMap((i) => caCertsAndOcspData(i).flatMap((e) => e.ocsp)),
    allCaCerts: (now) =>
      trust.visibleInstances(now).flatMap((i) => subjectsAndCaCerts(i).map((ca) => ca.cert)),
    isOcspResponderCert: (ca, ocspCert, now) =>
      trust
        .visibleInstances(now)
        .some((i) =>
          caCertsAndOcspData(i)
            .filter((e) => bytesEqual(e.ca.der, ca.der))
            .some((e) => e.ocsp.some((c) => bytesEqual(c.der, ocspCert.der))),
        ),
    subjectName: () => {
      throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, 'subjectName is not implemented here (see src/binding)');
    },
  };
}

function ocspFreshnessSeconds(trust: TrustContext): number {
  // The main instance is never filtered by expiry, so any `now` finds it.
  const main = trust.visibleInstances(new Date(0)).find((i) => i.instanceId === trust.mainInstance);
  if (!main) {
    throw new CodedError(
      ErrorCodes.X_INTERNAL_ERROR,
      `Shared params for instance identifier ${trust.mainInstance} not found`,
    );
  }
  return main.ocspFreshnessSeconds;
}

function getCaCert(trust: TrustContext, instance: string, cert: TrustedCert, now: Date): ApprovedCa {
  const inst = trust.visibleInstances(now).find((i) => i.instanceId === instance);
  if (!inst) {
    throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, `Shared params for instance identifier ${instance} not found`);
  }
  const issuer = issuerDer(cert.cert);
  const ca = subjectsAndCaCerts(inst).find((c) => x500Equal(c.cert.subjectDer, issuer));
  if (!ca) {
    throw new CodedError(
      ErrorCodes.X_INTERNAL_ERROR,
      'Certificate is not issued by approved certification service provider.',
    );
  }
  return ca;
}

/** HashMap<X500Name, cert>.values() with put-order keys: dedupe by BC-equal subject, last value wins. */
function subjectsAndCaCerts(inst: InstanceTrust): ApprovedCa[] {
  const out: ApprovedCa[] = [];
  for (const ca of inst.approvedCas) {
    const idx = out.findIndex((o) => x500Equal(o.cert.subjectDer, ca.cert.subjectDer));
    if (idx >= 0) out[idx] = ca;
    else out.push(ca);
  }
  return out;
}

/** HashMap<X509Certificate, List<OcspInfo>>: dedupe by CA DER, last list wins. */
function caCertsAndOcspData(inst: InstanceTrust): { ca: TrustedCert; ocsp: TrustedCert[] }[] {
  const out: { ca: TrustedCert; ocsp: TrustedCert[] }[] = [];
  for (const ca of inst.approvedCas) {
    const entry = { ca: ca.cert, ocsp: ca.ocspResponderCerts };
    const idx = out.findIndex((o) => bytesEqual(o.ca.der, ca.cert.der));
    if (idx >= 0) out[idx] = entry;
    else out.push(entry);
  }
  return out;
}
