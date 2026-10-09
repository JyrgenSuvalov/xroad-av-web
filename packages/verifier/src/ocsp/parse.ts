/**
 * OCSP response parsing (RFC 6960 §4.2.1) on asn1js, with the BouncyCastle
 * OCSPResp / BasicOCSPResp / SingleResp semantics the verifier relies on.
 *
 *   parseOcspResp(der)         - `new OCSPResp(bytes)`: the outer OCSPResponse.
 *                                Throws OcspParseError (Java IOException) when
 *                                the bytes are not an OCSPResponse.
 *   basicResponse(resp)        - `(BasicOCSPResp) resp.getResponseObject()` plus
 *                                `getResponses()[0]` access. Throws a plain Error
 *                                (Java NPE / ClassCastException / OCSPException,
 *                                which the caller maps to internal_error) when
 *                                responseBytes is absent, not id-pkix-ocsp-basic,
 *                                or does not decode.
 *
 * Embedded certificates (`certs [0]`) are kept as raw DER and NOT parsed here:
 * OcspVerifier tries the globalconf candidates first, and a corrupted embedded
 * copy must not fail verification when a globalconf cert matches (tamper
 * `ocsp-embedded-cert-byte-changed` → ok).
 *
 * The BasicOCSPResponse is parsed lazily and memoised per OcspResp.
 */
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { elementDer, generalizedTime, integerValue, octetStringBytes, primitiveBytes } from '../trust/der';

export const OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';

/** Java IOException from `new OCSPResp(bytes)`. */
export class OcspParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OcspParseError';
  }
}

export interface CertIdValue {
  hashAlgorithmOid: string;
  /** DER of the AlgorithmIdentifier parameters; null when absent. */
  hashAlgorithmParams: Uint8Array | null;
  issuerNameHash: Uint8Array;
  issuerKeyHash: Uint8Array;
  serialNumber: bigint;
}

export type CertStatus =
  | { kind: 'good' }
  | { kind: 'revoked'; revocationTime: Date }
  | { kind: 'unknown' };

export interface SingleResp {
  certId: CertIdValue;
  status: CertStatus;
  thisUpdate: Date;
  nextUpdate: Date | null;
}

export type ResponderId = { byName: Uint8Array } | { byKey: Uint8Array };

export interface BasicOcspResp {
  /** Original encoding of tbsResponseData (the signed bytes). */
  tbsResponseData: Uint8Array;
  responderId: ResponderId;
  producedAt: Date;
  responses: SingleResp[];
  signatureAlgorithm: pkijs.AlgorithmIdentifier;
  /** BIT STRING contents without the unused-bits octet. */
  signature: Uint8Array;
  /** certs [0], raw DER of each element, document order. */
  certs: Uint8Array[];
}

export interface OcspResp {
  /** The decoded EncapsulatedOCSPValue bytes. */
  der: Uint8Array;
  responseStatus: number;
  responseType: string | null;
  /** responseBytes.response OCTET STRING contents; null when responseBytes is absent. */
  responseBytes: Uint8Array | null;
  /** Memo for basicResponse(). */
  basic?: BasicOcspResp;
}

const ctx = (el: asn1js.AsnType, tag: number) => el.idBlock.tagClass === 3 && el.idBlock.tagNumber === tag;
const children = (el: asn1js.AsnType): asn1js.AsnType[] =>
  el.idBlock.isConstructed ? ((el.valueBlock as unknown as { value: asn1js.AsnType[] }).value ?? []) : [];

function fail(msg: string): never {
  throw new Error(msg);
}

export function parseOcspResp(der: Uint8Array): OcspResp {
  const parsed = asn1js.fromBER(der);
  if (parsed.offset === -1 || parsed.result.error) throw new OcspParseError(`malformed OCSP response: ${parsed.result.error}`);
  const seq = parsed.result;
  if (!(seq instanceof asn1js.Sequence)) throw new OcspParseError('malformed OCSP response: not a SEQUENCE');
  const [status, bytes] = children(seq);
  if (!(status instanceof asn1js.Enumerated)) throw new OcspParseError('malformed OCSP response: no responseStatus');
  let responseType: string | null = null;
  let responseBytes: Uint8Array | null = null;
  if (bytes) {
    const rb = ctx(bytes, 0) ? children(bytes)[0] : undefined;
    const [type, octets] = rb instanceof asn1js.Sequence ? children(rb) : [];
    if (!(type instanceof asn1js.ObjectIdentifier) || !(octets instanceof asn1js.OctetString)) {
      throw new OcspParseError('malformed OCSP response: bad responseBytes');
    }
    responseType = type.valueBlock.toString();
    responseBytes = octetStringBytes(octets);
  }
  return { der, responseStatus: status.valueBlock.valueDec, responseType, responseBytes };
}

/** `(BasicOCSPResp) resp.getResponseObject()`; throws a plain Error on anything Java would throw for. */
export function basicResponse(resp: OcspResp): BasicOcspResp {
  if (resp.basic) return resp.basic;
  if (!resp.responseBytes) fail('NullPointerException: OCSP response has no responseBytes');
  if (resp.responseType !== OID_OCSP_BASIC) fail(`ClassCastException: OCSP response type ${resp.responseType} is not basic`);
  resp.basic = parseBasic(resp.responseBytes);
  return resp.basic;
}

function parseBasic(bytes: Uint8Array): BasicOcspResp {
  const parsed = asn1js.fromBER(bytes);
  if (parsed.offset === -1 || parsed.result.error) fail('OCSPException: problem decoding BasicOCSPResponse');
  const [tbs, sigAlg, sig, certsEl] = children(parsed.result);
  if (!(tbs instanceof asn1js.Sequence) || !(sigAlg instanceof asn1js.Sequence) || !(sig instanceof asn1js.BitString)) {
    fail('OCSPException: malformed BasicOCSPResponse');
  }
  const certs: Uint8Array[] = [];
  if (certsEl) {
    const list = ctx(certsEl, 0) ? children(certsEl)[0] : undefined;
    if (!(list instanceof asn1js.Sequence)) fail('OCSPException: malformed BasicOCSPResponse certs');
    for (const c of children(list)) certs.push(elementDer(c));
  }

  const tbsKids = children(tbs);
  let i = 0;
  if (tbsKids[i] && ctx(tbsKids[i]!, 0)) i++; // version [0] EXPLICIT
  const rid = tbsKids[i++];
  const producedAtEl = tbsKids[i++];
  const responsesEl = tbsKids[i++];
  if (!rid || !(producedAtEl instanceof asn1js.GeneralizedTime) || !(responsesEl instanceof asn1js.Sequence)) {
    fail('OCSPException: malformed ResponseData');
  }
  let responderId: ResponderId;
  const ridInner = children(rid)[0];
  if (ctx(rid, 1) && ridInner instanceof asn1js.Sequence) responderId = { byName: elementDer(ridInner) };
  else if (ctx(rid, 2) && ridInner instanceof asn1js.OctetString) responderId = { byKey: octetStringBytes(ridInner) };
  else fail('OCSPException: malformed ResponderID');
  const producedAt = generalizedTime(producedAtEl) ?? fail('OCSPException: bad producedAt');

  return {
    tbsResponseData: elementDer(tbs),
    responderId,
    producedAt,
    responses: children(responsesEl).map(parseSingle),
    signatureAlgorithm: new pkijs.AlgorithmIdentifier({ schema: sigAlg }),
    signature: primitiveBytes(sig),
    certs,
  };
}

function parseSingle(el: asn1js.AsnType): SingleResp {
  const [certIdEl, statusEl, thisUpdateEl, ...rest] = children(el);
  if (!(certIdEl instanceof asn1js.Sequence) || !statusEl || !(thisUpdateEl instanceof asn1js.GeneralizedTime)) {
    fail('OCSPException: malformed SingleResponse');
  }
  let nextUpdate: Date | null = null;
  const nu = rest.find((r) => ctx(r, 0));
  if (nu) {
    const t = children(nu)[0];
    nextUpdate = (t instanceof asn1js.GeneralizedTime ? generalizedTime(t) : null) ?? fail('OCSPException: bad nextUpdate');
  }
  return {
    certId: parseCertId(certIdEl),
    status: parseStatus(statusEl),
    thisUpdate: generalizedTime(thisUpdateEl) ?? fail('OCSPException: bad thisUpdate'),
    nextUpdate,
  };
}

function parseCertId(el: asn1js.AsnType): CertIdValue {
  const [alg, nameHash, keyHash, serial] = children(el);
  const [oid, params] = alg instanceof asn1js.Sequence ? children(alg) : [];
  if (
    !(oid instanceof asn1js.ObjectIdentifier) ||
    !(nameHash instanceof asn1js.OctetString) ||
    !(keyHash instanceof asn1js.OctetString) ||
    !(serial instanceof asn1js.Integer)
  ) {
    fail('OCSPException: malformed CertID');
  }
  return {
    hashAlgorithmOid: oid.valueBlock.toString(),
    hashAlgorithmParams: params ? elementDer(params) : null,
    issuerNameHash: octetStringBytes(nameHash),
    issuerKeyHash: octetStringBytes(keyHash),
    serialNumber: integerValue(serial),
  };
}

/** CertStatus CHOICE: good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo, unknown [2] IMPLICIT NULL. */
function parseStatus(el: asn1js.AsnType): CertStatus {
  if (ctx(el, 0)) return { kind: 'good' };
  if (ctx(el, 2)) return { kind: 'unknown' };
  if (ctx(el, 1)) {
    const t = children(el)[0];
    const time = t instanceof asn1js.GeneralizedTime ? generalizedTime(t) : null;
    if (!time) fail('OCSPException: malformed RevokedInfo');
    return { kind: 'revoked', revocationTime: time };
  }
  fail('OCSPException: unknown CertStatus');
}
