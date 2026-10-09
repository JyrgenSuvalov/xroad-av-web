/**
 * OCSP verification: CertHelper.getOcspResponseForCert (CH:122-135) and
 * OcspVerifier.verifyValidityAndStatus (OV:120-420)
 *
 *   createCertId(issuer, serial)                       → CertIdValue (SHA-1, NULL params)
 *   findOcspResponseForCert(subject, issuer, resps)    → OcspResp | null
 *   verifyValidityAndStatus(resp, subject, issuer, atDate, ctx) → OcspResult
 *
 * Errors are UNPREFIXED here (the caller, certpath, adds `invalid_cert_path.`):
 *   incorrect_validation_info  "OCSP response does not apply to certificate (sn = <dec>)"
 *   incorrect_validation_info  "Could not find OCSP certificate for responder ID"
 *   incorrect_validation_info  "Signature on OCSP response is not valid"
 *   incorrect_validation_info  "OCSP responder is not authorized for given CA"
 *   incorrect_validation_info  "OCSP response is too old (thisUpdate: <OffsetDateTime>)"
 *   incorrect_validation_info  "OCSP nextUpdate is too old, atDate: … nextUpdate: …"
 *   cert_validation            "OCSP response indicates certificate status is UNKNOWN|REVOKED (date: …)"
 *   internal_error             no/other responseBytes, undecodable BasicOCSPResponse,
 *                              empty responses, unsupported signature algorithm, …
 *
 * Responder lookup order (OV:330-370): globalconf ocsp/cert of every visible
 * instance, then every visible CA cert, then the certs embedded in the response.
 * The first match wins. Embedded certs are decoded only when the globalconf
 * candidates did not match (divergence: Java decodes them eagerly, so an
 * UNPARSABLE embedded cert would fail there even when a globalconf cert matches;
 * a parsable-but-corrupted one, as in tamper ocsp-embedded-cert-byte-changed,
 * behaves identically).
 *
 * Not checked (as in Java): producedAt, nonce, extensions, the responder cert's
 * validity / keyUsage / revocation.
 */
import * as asn1js from 'asn1js';
import type * as pkijs from 'pkijs';
import { CodedError, ErrorCodes } from '../util/errors';
import type { TrustContext, TrustedCert } from '../types';
import { trustQueries } from '../trust/queries';
import { bytesEqual } from '../util/bytes';
import { sha1, UnsupportedAlgorithmError, verifyByOid } from '../trust/crypto';
import { issuerDer, subjectDer, x500Equal } from '../trust/x500';
import { parseCertificateDer } from '../xades/cert';
import { basicResponse, type BasicOcspResp, type CertIdValue, type OcspResp, type SingleResp } from './parse';
import { jdkX500Equal } from './names';

export const OID_SHA1 = '1.3.14.3.2.26';
export const OID_KP_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
const OID_EXT_KEY_USAGE = '2.5.29.37';
const DER_NULL = new Uint8Array([0x05, 0x00]);

export interface OcspResult {
  /** The response that was verified. */
  response: OcspResp;
  /** The responder certificate that verified the response signature. */
  responderCert: TrustedCert;
  /** Where the responder cert came from (diagnostics). */
  responderSource: 'globalconf-ocsp' | 'globalconf-ca' | 'embedded';
  producedAt: Date;
  thisUpdate: Date;
  nextUpdate: Date | null;
}

export interface OcspVerifyContext {
  trust: TrustContext;
  /** Wall clock, only for the non-main instance visibility filter. */
  now: Date;
}

/** TrustedCert for a parsed certificate. */
export function trustedCert(der: Uint8Array, cert: pkijs.Certificate = parseCertificateDer(der).cert): TrustedCert {
  return { der, cert, subjectDer: subjectDer(cert) };
}

/** SubjectPublicKeyInfo.subjectPublicKey BIT STRING contents (BC getPublicKeyData().getBytes()). */
export function publicKeyBits(cert: pkijs.Certificate): Uint8Array {
  return new Uint8Array(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
}

/** CryptoUtils.createCertId: CertificateID(SHA-1 with NULL params, issuer, serial). */
export async function createCertId(issuer: TrustedCert, serialNumber: bigint): Promise<CertIdValue> {
  return {
    hashAlgorithmOid: OID_SHA1,
    hashAlgorithmParams: DER_NULL,
    issuerNameHash: await sha1(issuer.subjectDer),
    issuerKeyHash: await sha1(publicKeyBits(issuer.cert)),
    serialNumber,
  };
}

/** BC CertificateID.equals: ASN.1 equality of the CertID (absent params ≠ NULL params). */
export function certIdEquals(a: CertIdValue, b: CertIdValue): boolean {
  const pa = a.hashAlgorithmParams;
  const pb = b.hashAlgorithmParams;
  return (
    a.hashAlgorithmOid === b.hashAlgorithmOid &&
    (pa === null || pb === null ? pa === pb : bytesEqual(pa, pb)) &&
    bytesEqual(a.issuerNameHash, b.issuerNameHash) &&
    bytesEqual(a.issuerKeyHash, b.issuerKeyHash) &&
    a.serialNumber === b.serialNumber
  );
}

function firstSingle(resp: OcspResp): { basic: BasicOcspResp; single: SingleResp } {
  const basic = basicResponse(resp);
  const single = basic.responses[0];
  if (!single) throw new Error('ArrayIndexOutOfBoundsException: OCSP response has no SingleResponse');
  return { basic, single };
}

/** CertHelper.getOcspResponseForCert: the FIRST response whose responses[0].certID matches. */
export async function findOcspResponseForCert(
  subject: pkijs.Certificate,
  issuer: TrustedCert,
  responses: readonly OcspResp[],
): Promise<OcspResp | null> {
  const certId = await createCertId(issuer, subject.serialNumber.toBigInt());
  for (const resp of responses) {
    if (certIdEquals(certId, firstSingle(resp).single.certId)) return resp;
  }
  return null;
}

export async function verifyValidityAndStatus(
  response: OcspResp,
  subject: pkijs.Certificate,
  issuer: TrustedCert,
  atDate: Date,
  ctx: OcspVerifyContext,
): Promise<OcspResult> {
  const q = trustQueries(ctx.trust);
  const freshness = q.ocspFreshnessSeconds(); // OcspVerifier constructor
  const { basic, single } = firstSingle(response);

  // 1. CertID
  const serial = subject.serialNumber.toBigInt();
  if (!certIdEquals(single.certId, await createCertId(issuer, serial))) {
    throw validationInfo(`OCSP response does not apply to certificate (sn = ${serial.toString()})`);
  }

  // 2. responder certificate
  const found = await getOcspCert(basic, ctx);
  if (!found) throw validationInfo('Could not find OCSP certificate for responder ID');

  // 3. signature
  if (!(await verifySignature(basic, found.cert))) throw validationInfo('Signature on OCSP response is not valid');

  // 4. authorisation
  if (!(await isAuthorizedOcspSigner(found.cert, issuer, ctx))) {
    throw validationInfo('OCSP responder is not authorized for given CA');
  }

  // 5. freshness: thisUpdate.before(atDate − F s)
  const allowed = atDate.getTime() - freshness * 1000;
  if (single.thisUpdate.getTime() < allowed) {
    throw validationInfo(`OCSP response is too old (thisUpdate: ${javaOffsetDateTime(single.thisUpdate)})`);
  }

  // 6. nextUpdate
  if (ctx.trust.verifyOcspNextUpdate && single.nextUpdate && single.nextUpdate.getTime() < atDate.getTime()) {
    throw validationInfo(
      `OCSP nextUpdate is too old, atDate: ${javaOffsetDateTime(atDate)} nextUpdate: ${javaOffsetDateTime(single.nextUpdate)}`,
    );
  }

  // 7. status
  if (single.status.kind !== 'good') {
    const s =
      single.status.kind === 'unknown' ? 'UNKNOWN' : `REVOKED (date: ${javaDateTime(single.status.revocationTime)})`;
    throw new CodedError(ErrorCodes.X_CERT_VALIDATION, `OCSP response indicates certificate status is ${s}`);
  }

  return {
    response,
    responderCert: found.cert,
    responderSource: found.source,
    producedAt: basic.producedAt,
    thisUpdate: single.thisUpdate,
    nextUpdate: single.nextUpdate,
  };
}

function validationInfo(msg: string): CodedError {
  return new CodedError(ErrorCodes.X_INCORRECT_VALIDATION_INFO, msg);
}

/** OcspVerifier.getOcspCert: first candidate matching the ResponderID. */
async function getOcspCert(
  basic: BasicOcspResp,
  ctx: OcspVerifyContext,
): Promise<{ cert: TrustedCert; source: OcspResult['responderSource'] } | null> {
  const q = trustQueries(ctx.trust);
  const rid = basic.responderId;
  const matches = async (c: TrustedCert) =>
    'byName' in rid ? x500Equal(c.subjectDer, rid.byName) : bytesEqual(await sha1(publicKeyBits(c.cert)), rid.byKey);

  for (const c of q.ocspResponderCertificates(ctx.now)) if (await matches(c)) return { cert: c, source: 'globalconf-ocsp' };
  for (const c of q.allCaCerts(ctx.now)) if (await matches(c)) return { cert: c, source: 'globalconf-ca' };
  for (const der of basic.certs) {
    const c = trustedCert(der); // throws → internal_error (Java CertificateException is not expected here)
    if (await matches(c)) return { cert: c, source: 'embedded' };
  }
  return null;
}

async function verifySignature(basic: BasicOcspResp, responder: TrustedCert): Promise<boolean> {
  try {
    return await verifyByOid({
      cert: responder.cert,
      signatureAlgorithm: basic.signatureAlgorithm,
      data: basic.tbsResponseData,
      signature: basic.signature,
    });
  } catch (e) {
    if (e instanceof UnsupportedAlgorithmError) {
      // Java: OperatorCreationException from createDefaultContentVerifier → internal_error
      throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, e.message, { cause: e });
    }
    throw e;
  }
}

/** OcspVerifier.isAuthorizedOcspSigner (OV:384-420). */
async function isAuthorizedOcspSigner(ocsp: TrustedCert, issuer: TrustedCert, ctx: OcspVerifyContext): Promise<boolean> {
  if (trustQueries(ctx.trust).isOcspResponderCert(issuer, ocsp, ctx.now)) return true;
  if (bytesEqual(ocsp.der, issuer.der)) return true;
  if (jdkX500Equal(issuerDer(ocsp.cert), issuer.subjectDer)) {
    if (!(await certSignedBy(ocsp.cert, issuer.cert))) return false;
    return extendedKeyUsage(ocsp.cert)?.includes(OID_KP_OCSP_SIGNING) ?? false;
  }
  return false;
}

/** X509Certificate.verify(issuerKey) as a boolean (GeneralSecurityException → false). */
export async function certSignedBy(cert: pkijs.Certificate, issuer: pkijs.Certificate): Promise<boolean> {
  try {
    return await verifyByOid({
      cert: issuer,
      signatureAlgorithm: cert.signatureAlgorithm,
      data: new Uint8Array(cert.tbsView),
      signature: new Uint8Array(cert.signatureValue.valueBlock.valueHexView),
    });
  } catch {
    return false;
  }
}

/** X509Certificate.getExtendedKeyUsage(): null when absent; throws (→ internal_error) when malformed. */
export function extendedKeyUsage(cert: pkijs.Certificate): string[] | null {
  const ext = cert.extensions?.find((e) => e.extnID === OID_EXT_KEY_USAGE);
  if (!ext) return null;
  const asn = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
  if (asn.offset === -1 || !(asn.result instanceof asn1js.Sequence)) {
    throw new Error('CertificateParsingException: malformed ExtendedKeyUsage');
  }
  return asn.result.valueBlock.value.map((o) => {
    if (!(o instanceof asn1js.ObjectIdentifier)) throw new Error('CertificateParsingException: malformed ExtendedKeyUsage');
    return o.valueBlock.toString();
  });
}

const p2 = (n: number) => String(n).padStart(2, '0');

/**
 * TimeUtils.toOffsetDateTime(date).toString() in UTC (the reference runs with
 * TZ=UTC): `uuuu-MM-ddTHH:mm[:ss[.SSS]]Z`, seconds omitted when zero together
 * with the millis.
 */
export function javaOffsetDateTime(d: Date): string {
  const base = `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())}T${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`;
  const s = d.getUTCSeconds();
  const ms = d.getUTCMilliseconds();
  if (s === 0 && ms === 0) return `${base}Z`;
  return `${base}:${p2(s)}${ms ? '.' + String(ms).padStart(3, '0') : ''}Z`;
}

/** String.format("%tF %tT", date) in UTC. */
export function javaDateTime(d: Date): string {
  return `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`;
}
