/**
 * TimestampVerifier.verify(tsToken, stampedData, tspCerts) port (7.8.3).
 * See README.md.
 *
 *   verifyTimestamp(tokenDer, stampedData, trust, now)       - parse + verify
 *   verifyTimestampToken(token, stampedData, trust, now)     - verify a parsed token
 *
 * Order and codes:
 *   1. imprint: H(messageImprint.hashAlgorithm, stampedData) ≠ hashedMessage
 *        → malformed_signature "Timestamp hashes do not match"
 *        (unsupported imprint algorithm → internal_error)
 *   2. no approved TSA cert in visible instances → mlog.no_timestamping_provider_found
 *   3. first config TSA cert matched by the SignerInfo SID (BC SignerId.match)
 *        none → mlog.tsp_certificate_not_found
 *   4. BC SignerInformation.verify(config cert) → any failure
 *        → mlog.timestamp_signer_verification_failed
 * Certificates embedded in the token are never used.
 */

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import type { TrustContext, TrustedCert } from '../types';
import { CodedError, ErrorCodes } from '../util/errors';
import { UnsupportedAlgorithmError, digestByOid, sha1, verifyByOid } from '../trust/crypto';
import { bytesEqual } from '../util/bytes';
import { elementDer, octetStringBytes, primitiveBytes, timeValue } from '../trust/der';
import { trustQueries } from '../trust/queries';
import { issuerDer, x500Equal } from '../trust/x500';
import { parseTimestampToken, type SignerIdentifier, type TimestampToken } from './token';

export interface TimestampVerification {
  /** TSTInfo.genTime = atDate for the signing-cert/OCSP checks. */
  genTime: Date;
  /** The approved TSA cert from the global configuration that signed the token. */
  tsaCert: TrustedCert;
  token: TimestampToken;
}

const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';
const OID_COUNTER_SIGNATURE = '1.2.840.113549.1.9.6';
const OID_CMS_ALGORITHM_PROTECT = '1.2.840.113549.1.9.52';
const OID_SKI = '2.5.29.14';

export async function verifyTimestamp(
  tokenDer: Uint8Array,
  stampedData: Uint8Array,
  trust: TrustContext,
  now: Date,
): Promise<TimestampVerification> {
  return verifyTimestampToken(parseTimestampToken(tokenDer), stampedData, trust, now);
}

export async function verifyTimestampToken(
  token: TimestampToken,
  stampedData: Uint8Array,
  trust: TrustContext,
  now: Date,
): Promise<TimestampVerification> {
  let computed: Uint8Array;
  try {
    computed = await digestByOid(token.imprintAlgorithm, stampedData);
  } catch (e) {
    throw new CodedError(
      ErrorCodes.X_INTERNAL_ERROR,
      `Failed to create digest calculator for algorithm: ${token.imprintAlgorithm}`,
      { cause: e },
    );
  }
  if (!bytesEqual(computed, token.imprint)) {
    throw new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, 'Timestamp hashes do not match');
  }

  const tspCerts = trustQueries(trust).tspCertificates(now);
  if (tspCerts.length === 0) {
    throw new CodedError(ErrorCodes.NO_TIMESTAMPING_PROVIDER_FOUND, 'No TSP service providers are configured.');
  }

  const tsaCert = await findTspCertificate(token.sid, tspCerts);
  if (!tsaCert) {
    throw new CodedError(ErrorCodes.TSP_CERTIFICATE_NOT_FOUND, 'Could not find TSP certificate for timestamp');
  }

  try {
    await verifySignerInfo(token, tsaCert.cert);
  } catch (e) {
    throw new CodedError(
      ErrorCodes.TIMESTAMP_SIGNER_VERIFICATION_FAILED,
      'Failed to verify timestamp signer information',
      { cause: e },
    );
  }

  return { genTime: token.genTime, tsaCert, token };
}

/** TimestampVerifier.getTspCertificate: first cert matched by BC SignerId.match. */
export async function findTspCertificate(sid: SignerIdentifier, certs: TrustedCert[]): Promise<TrustedCert | null> {
  for (const c of certs) {
    if (await signerIdMatches(sid, c.cert)) return c;
  }
  return null;
}

/** BC X509CertificateHolderSelector.match. */
async function signerIdMatches(sid: SignerIdentifier, cert: pkijs.Certificate): Promise<boolean> {
  if (sid.kind === 'issuerSerial') {
    return cert.serialNumber.toBigInt() === sid.serial && x500Equal(issuerDer(cert), sid.issuerDer);
  }
  const ext = cert.extensions?.find((e) => e.extnID === OID_SKI);
  if (!ext) {
    // MSOutlookKeyIdCalculator: SHA-1 of the DER SubjectPublicKeyInfo.
    const spki = new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false));
    return bytesEqual(sid.keyId, await sha1(spki));
  }
  const inner = asn1js.fromBER(primitiveBytes(ext.extnValue));
  if (!(inner.result instanceof asn1js.OctetString)) return false;
  return bytesEqual(sid.keyId, octetStringBytes(inner.result));
}

class SignerInfoError extends Error {}

/**
 * BC 1.84 SignerInformation.verify(SignerInformationVerifier with associated
 * cert): signingTime validity, content-type, cmsAlgorithmProtect, message-digest,
 * countersignature placement, then the signature over DER(signedAttrs).
 * Throws on any failure (the caller maps everything to one fault code).
 */
async function verifySignerInfo(token: TimestampToken, cert: pkijs.Certificate): Promise<void> {
  const si = token.signerInfo;
  const signed = si.signedAttrs?.attributes ?? [];
  const unsigned = si.unsignedAttrs?.attributes ?? [];

  const single = (oid: string, name: string): asn1js.AsnType | null => {
    if (unsigned.some((a) => a.type === oid)) throw new SignerInfoError(`The ${name} attribute MUST NOT be an unsigned attribute`);
    const all = signed.filter((a) => a.type === oid);
    if (all.length === 0) return null;
    if (all.length > 1) throw new SignerInfoError(`multiple instances of the ${name} attribute`);
    if (all[0]!.values.length !== 1) throw new SignerInfoError(`A ${name} attribute MUST have a single attribute value`);
    return all[0]!.values[0] as asn1js.AsnType;
  };

  // signingTime: the verifier cert must be valid at it (inclusive bounds).
  const st = single(OID_SIGNING_TIME, 'signing-time');
  if (st) {
    const when = timeValue(st);
    if (!when) throw new SignerInfoError('signing-time is not a Time');
    if (when < cert.notBefore.value || when > cert.notAfter.value) {
      throw new SignerInfoError('verifier not valid at signingTime');
    }
  }

  // content-type
  const ct = single(OID_CONTENT_TYPE, 'content-type');
  if (!ct) throw new SignerInfoError('The content-type attribute type MUST be present whenever signed attributes are present');
  if (!(ct instanceof asn1js.ObjectIdentifier) || ct.valueBlock.toString() !== token.eContentType) {
    throw new SignerInfoError('content-type attribute value does not match eContentType');
  }

  // cmsAlgorithmProtect (RFC 6211)
  if (unsigned.some((a) => a.type === OID_CMS_ALGORITHM_PROTECT)) {
    throw new SignerInfoError('A cmsAlgorithmProtect attribute MUST be a signed attribute');
  }
  const protect = signed.filter((a) => a.type === OID_CMS_ALGORITHM_PROTECT);
  if (protect.length > 1) throw new SignerInfoError('Only one instance of a cmsAlgorithmProtect attribute can be present');
  if (protect.length === 1) checkAlgorithmProtection(protect[0]!, si);

  // message-digest
  const md = single(OID_MESSAGE_DIGEST, 'message-digest');
  if (!md) throw new SignerInfoError('the message-digest signed attribute type MUST be present');
  if (!(md instanceof asn1js.OctetString)) throw new SignerInfoError('message-digest attribute value not of ASN.1 type OCTET STRING');
  const contentDigest = await digestByOid(si.digestAlgorithm.algorithmId, token.eContent);
  if (!bytesEqual(contentDigest, octetStringBytes(md))) {
    throw new SignerInfoError('message-digest attribute value does not match calculated value');
  }

  // countersignature placement
  if (signed.some((a) => a.type === OID_COUNTER_SIGNATURE)) {
    throw new SignerInfoError('A countersignature attribute MUST NOT be a signed attribute');
  }
  for (const a of unsigned.filter((x) => x.type === OID_COUNTER_SIGNATURE)) {
    if (a.values.length < 1) throw new SignerInfoError('A countersignature attribute MUST contain at least one AttributeValue');
  }

  const ok = await verifyByOid({
    cert,
    signatureAlgorithm: si.signatureAlgorithm,
    digestAlgorithm: si.digestAlgorithm,
    data: derSignedAttributes(si),
    signature: primitiveBytes(si.signature),
  }).catch((e: unknown) => {
    if (e instanceof UnsupportedAlgorithmError) throw new SignerInfoError(e.message);
    throw e;
  });
  if (!ok) throw new SignerInfoError('signature does not verify');
}

/**
 * getEncodedSignedAttributes = signedAttributeSet.getEncoded(DER): a SET with
 * the element encodings in DER (sorted) order. Elements are taken as encoded
 * in the token (DER from any conforming TSA).
 */
function derSignedAttributes(si: pkijs.SignerInfo): Uint8Array {
  const raw = new Uint8Array(si.signedAttrs!.encodedValue);
  const parsed = asn1js.fromBER(raw);
  const items =
    parsed.offset === -1 ? [] : (parsed.result.valueBlock as unknown as { value: asn1js.AsnType[] }).value ?? [];
  const encs = items.map(elementDer).sort(compareDer);
  const body = new Uint8Array(encs.reduce((n, e) => n + e.length, 0));
  let off = 0;
  for (const e of encs) {
    body.set(e, off);
    off += e.length;
  }
  return concat([0x31, ...derLength(body.length)], body);
}

/** BC DERSet ordering: lexicographic on encodings; a proper prefix sorts first. */
function compareDer(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}

function derLength(len: number): number[] {
  if (len < 0x80) return [len];
  const out: number[] = [];
  for (let l = len; l > 0; l >>>= 8) out.unshift(l & 0xff);
  return [0x80 | out.length, ...out];
}

function concat(head: number[], body: Uint8Array): Uint8Array {
  const out = new Uint8Array(head.length + body.length);
  out.set(head, 0);
  out.set(body, head.length);
  return out;
}

/** CMSAlgorithmProtection ::= SEQUENCE { digestAlgorithm, signatureAlgorithm [1] IMPLICIT OPTIONAL, macAlgorithm [2] IMPLICIT OPTIONAL } */
function checkAlgorithmProtection(attr: pkijs.Attribute, si: pkijs.SignerInfo): void {
  if (attr.values.length !== 1) throw new SignerInfoError('cmsAlgorithmProtect must have a single value');
  const seq = attr.values[0] as asn1js.AsnType;
  if (!(seq instanceof asn1js.Sequence)) throw new SignerInfoError('malformed cmsAlgorithmProtect');
  const [digest, ...rest] = seq.valueBlock.value;
  const sigAlg = rest.find((e) => e.idBlock.tagClass === 3 && e.idBlock.tagNumber === 1);
  const sigItems = sigAlg ? ((sigAlg.valueBlock as unknown as { value: asn1js.AsnType[] }).value ?? []) : null;
  if (!algEquivalent(digest ? algParts(digest) : null, si.digestAlgorithm)) {
    throw new SignerInfoError('CMS Algorithm Identifier Protection check failed for digestAlgorithm');
  }
  if (!algEquivalent(sigItems ? algPartsOf(sigItems) : null, si.signatureAlgorithm)) {
    throw new SignerInfoError('CMS Algorithm Identifier Protection check failed for signatureAlgorithm');
  }
}

type AlgParts = { oid: string; params: asn1js.AsnType | undefined };

function algParts(el: asn1js.AsnType): AlgParts | null {
  return el instanceof asn1js.Sequence ? algPartsOf(el.valueBlock.value) : null;
}

function algPartsOf(items: asn1js.AsnType[]): AlgParts | null {
  const [oid, params] = items;
  return oid instanceof asn1js.ObjectIdentifier ? { oid: oid.valueBlock.toString(), params } : null;
}

/** CMSUtils.isEquivalent: same OID; params equal, or one absent and the other NULL. */
function algEquivalent(a: AlgParts | null, b: pkijs.AlgorithmIdentifier): boolean {
  if (!a || a.oid !== b.algorithmId) return false;
  const pa = a.params;
  const pb = b.algorithmParams as asn1js.AsnType | undefined;
  const isNull = (p: asn1js.AsnType | undefined) => p instanceof asn1js.Null;
  if (!pa || !pb) return (!pa || isNull(pa)) && (!pb || isNull(pb));
  return bytesEqual(elementDer(pa), elementDer(pb));
}
