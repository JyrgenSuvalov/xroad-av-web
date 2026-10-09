/**
 * RFC 3161 TimeStampToken parsing with the checks of
 * `new TimeStampToken(ContentInfo.getInstance(ASN1Primitive.fromByteArray(der)))`
 * (AsicContainerVerifier.getTimeStampToken, BC 1.84). See README.md.
 *
 * Fault codes (probed, test/timestamp/probe/probe-output.txt):
 *   - outer BER does not decode, or trailing bytes      → io_error   (IOException)
 *   - empty input                                       → internal_error (NPE)
 *   - not ContentInfo / not SignedData / eContentType ≠ id-ct-TSTInfo /
 *     signer count ≠ 1 / TSTInfo does not parse / no ESS signingCertificate(V2)
 *                                                       → internal_error
 */

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { CodedError, ErrorCodes } from '../util/errors';
import { generalizedTime, octetStringBytes, parseStrict, primitiveBytes } from '../trust/der';
import { nameDer } from '../trust/x500';

export const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
export const OID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
export const OID_AA_SIGNING_CERTIFICATE = '1.2.840.113549.1.9.16.2.12';
export const OID_AA_SIGNING_CERTIFICATE_V2 = '1.2.840.113549.1.9.16.2.47';

export type SignerIdentifier =
  | { kind: 'issuerSerial'; issuerDer: Uint8Array; serial: bigint }
  | { kind: 'ski'; keyId: Uint8Array };

export interface TimestampToken {
  readonly der: Uint8Array;
  readonly signedData: pkijs.SignedData;
  /** The single SignerInfo (TimeStampToken.tsaSignerInfo). */
  readonly signerInfo: pkijs.SignerInfo;
  readonly sid: SignerIdentifier;
  /** encapContentInfo.eContentType (always id-ct-TSTInfo after parsing). */
  readonly eContentType: string;
  /** eContent octets (the DER TSTInfo); BER-constructed segments concatenated. */
  readonly eContent: Uint8Array;
  readonly tstInfo: pkijs.TSTInfo;
  /** TSTInfo.messageImprint.hashAlgorithm OID. */
  readonly imprintAlgorithm: string;
  readonly imprint: Uint8Array;
  /** TSTInfo.genTime, java.util.Date precision (ms; finer digits truncated). */
  readonly genTime: Date;
}

const internal = (msg: string, cause?: unknown) => new CodedError(ErrorCodes.X_INTERNAL_ERROR, msg, { cause });

export function parseTimestampToken(der: Uint8Array): TimestampToken {
  if (der.length === 0) throw internal('Timestamp token is empty');
  const root = parseStrict(der);
  if (!root) throw new CodedError(ErrorCodes.X_IO_ERROR, 'Timestamp token is not valid ASN.1 (BER)');

  let contentInfo: pkijs.ContentInfo;
  try {
    contentInfo = new pkijs.ContentInfo({ schema: root });
  } catch (e) {
    throw internal('Timestamp token is not a CMS ContentInfo', e);
  }
  if (contentInfo.contentType !== OID_SIGNED_DATA) throw internal('TSP parsing error: Malformed content.');

  let signedData: pkijs.SignedData;
  try {
    signedData = new pkijs.SignedData({ schema: contentInfo.content });
  } catch (e) {
    throw internal('TSP parsing error: Malformed content.', e);
  }

  const eContentType = signedData.encapContentInfo.eContentType;
  if (eContentType !== OID_CT_TSTINFO) throw internal('ContentInfo object not for a time stamp.');

  if (signedData.signerInfos.length !== 1) {
    throw internal(
      `Time-stamp token signed by ${signedData.signerInfos.length} signers, but it must contain just the TSA signature.`,
    );
  }
  const signerInfo = signedData.signerInfos[0]!;
  const sid = signerIdentifier(signerInfo);

  const eContentOs = signedData.encapContentInfo.eContent;
  if (!eContentOs) throw internal('Timestamp token has no encapsulated TSTInfo');
  const eContent = octetStringBytes(eContentOs);
  const tstEl = parseStrict(eContent);
  if (!tstEl) throw internal('failed to construct sequence from byte[]: TSTInfo does not decode');
  let tstInfo: pkijs.TSTInfo;
  try {
    tstInfo = new pkijs.TSTInfo({ schema: tstEl });
  } catch (e) {
    throw internal('TSTInfo does not parse', e);
  }
  const genTimeEl = (tstEl as asn1js.Sequence).valueBlock.value[4];
  const genTime = genTimeEl instanceof asn1js.GeneralizedTime ? generalizedTime(genTimeEl) : null;
  if (!genTime) throw internal('TSTInfo genTime is not a valid GeneralizedTime');

  requireSigningCertificateAttribute(signerInfo);

  return {
    der,
    signedData,
    signerInfo,
    sid,
    eContentType,
    eContent,
    tstInfo,
    imprintAlgorithm: tstInfo.messageImprint.hashAlgorithm.algorithmId,
    imprint: primitiveBytes(tstInfo.messageImprint.hashedMessage),
    genTime,
  };
}

function signerIdentifier(si: pkijs.SignerInfo): SignerIdentifier {
  const sid = si.sid as unknown;
  if (sid instanceof pkijs.IssuerAndSerialNumber) {
    return { kind: 'issuerSerial', issuerDer: nameDer(sid.issuer), serial: sid.serialNumber.toBigInt() };
  }
  // subjectKeyIdentifier [0] IMPLICIT OCTET STRING
  if (sid instanceof asn1js.BaseBlock && sid.idBlock.tagClass === 3 && sid.idBlock.tagNumber === 0) {
    return { kind: 'ski', keyId: primitiveBytes(sid as asn1js.AsnType) };
  }
  throw internal('SignerInfo has an unknown SignerIdentifier');
}

/**
 * TimeStampToken constructor: id-aa-signingCertificate (v1, first ESSCertID used)
 * or id-aa-signingCertificateV2 must be present and parse. The ESSCertID hash is
 * NOT compared (X-Road never calls validate()).
 */
function requireSigningCertificateAttribute(si: pkijs.SignerInfo): void {
  const attrs = si.signedAttrs?.attributes;
  if (!attrs) throw internal('Timestamp SignerInfo has no signed attributes');
  const v1 = attrs.find((a) => a.type === OID_AA_SIGNING_CERTIFICATE);
  const attr = v1 ?? attrs.find((a) => a.type === OID_AA_SIGNING_CERTIFICATE_V2);
  if (!attr) throw internal('no signing certificate attribute found, time stamp invalid.');
  // SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies OPTIONAL }
  const value = attr.values[0] as asn1js.AsnType | undefined;
  const certs = value instanceof asn1js.Sequence ? value.valueBlock.value[0] : undefined;
  const first = certs instanceof asn1js.Sequence ? certs.valueBlock.value[0] : undefined;
  if (!(first instanceof asn1js.Sequence)) throw internal('malformed signing certificate attribute');
  const head = first.valueBlock.value[0];
  // ESSCertID starts with certHash OCTET STRING; ESSCertIDv2 with an optional AlgorithmIdentifier.
  const ok = v1 ? head instanceof asn1js.OctetString : head instanceof asn1js.OctetString || head instanceof asn1js.Sequence;
  if (!ok) throw internal('malformed ESSCertID in signing certificate attribute');
}
