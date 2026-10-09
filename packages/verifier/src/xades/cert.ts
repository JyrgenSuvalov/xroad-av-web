/**
 * Signing certificate: SignatureVerifier.getSigningCertificate (SV:231-245),
 * Signature.getSigningCertificate (SIG:255-257, Santuario
 * KeyInfo.getX509Certificate) and CertUtils.isSigningCert (CU:273-283).
 *
 *   getSigningCertificate(sig: SignatureModel) → SigningCertificate
 *
 * Santuario X509CertificateResolver (SANTUARIO-RULES §5): for each ds-namespace
 * child of ds:KeyInfo in document order, its direct ds:X509Certificate children,
 * or else those of its first nested ds:X509Data (recursively). The first such
 * certificate wins and is the only one parsed. A broken one aborts; later
 * certificates are not tried. Trailing bytes after the DER are ignored (JDK
 * CertificateFactory).
 *
 * Fault codes, in order:
 *   internal_error      ds:KeyInfo absent (Java NPE on getKeyInfo())
 *   malformed_signature "Signature does not contain signing certificate" (no ds:X509Certificate)
 *   internal_error      bad base64 padding (IllegalArgumentException) or the certificate
 *                       does not parse (Santuario KeyResolverException)
 *   internal_error      "Certificate does not contain keyUsage extension"
 *   malformed_signature "Certificate <subject> is not a signing certificate" (nonRepudiation bit not set)
 */
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { CodedError, ErrorCodes } from '../util/errors';
import { childElements, type XElement } from '../xml/safe';
import { decodeDsBase64, dsText } from './base64';
import { DS_NS, isDs, type SignatureModel } from './model';

export interface SigningCertificate {
  der: Uint8Array;
  cert: pkijs.Certificate;
}

const KEY_USAGE_OID = '2.5.29.15';

/** Parses the leading DER certificate; `der` is that certificate's exact encoding (trailing bytes dropped). */
export function parseCertificateDer(bytes: Uint8Array): SigningCertificate {
  const asn = asn1js.fromBER(bytes.slice().buffer as ArrayBuffer);
  if (asn.offset === -1) throw new Error(`certificate DER does not parse: ${asn.result.error}`);
  return { der: bytes.slice(0, asn.offset), cert: new pkijs.Certificate({ schema: asn.result }) };
}

export function getSigningCertificate(sig: SignatureModel): SigningCertificate {
  if (!sig.keyInfo) {
    throw new CodedError(
      ErrorCodes.X_INTERNAL_ERROR,
      'Cannot invoke "org.apache.xml.security.keys.KeyInfo.getX509Certificate()" because the return value of ' +
        '"org.apache.xml.security.signature.XMLSignature.getKeyInfo()" is null',
    );
  }
  const certEl = firstX509Certificate(sig.keyInfo);
  if (!certEl) throw new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, 'Signature does not contain signing certificate');
  const bytes = decodeDsBase64(dsText(certEl));
  let parsed: SigningCertificate;
  try {
    parsed = parseCertificateDer(bytes);
  } catch (e) {
    throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, `Cannot decode signing certificate: ${String(e)}`, { cause: e });
  }
  const { cert } = parsed;
  const nonRepudiation = keyUsageBit(cert, 1);
  if (nonRepudiation === undefined) {
    throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, 'Certificate does not contain keyUsage extension');
  }
  if (!nonRepudiation) {
    throw new CodedError(
      ErrorCodes.X_MALFORMED_SIGNATURE,
      `Certificate ${subjectString(cert)} is not a signing certificate`,
    );
  }
  return parsed;
}

function firstX509Certificate(keyInfo: XElement): XElement | undefined {
  for (const child of childElements(keyInfo)) {
    if (child.namespaceURI !== DS_NS) continue;
    const found = certificatesIn(child);
    if (found) return found;
  }
  return undefined;
}

function certificatesIn(el: XElement): XElement | undefined {
  const kids = childElements(el);
  const cert = kids.find((k) => isDs(k, 'X509Certificate'));
  if (cert) return cert;
  const nested = kids.find((k) => isDs(k, 'X509Data'));
  return nested && certificatesIn(nested);
}

/** Java X509Certificate.getKeyUsage()[bit]; undefined when there is no keyUsage extension. */
export function keyUsageBit(cert: pkijs.Certificate, bit: number): boolean | undefined {
  const ext = cert.extensions?.find((e) => e.extnID === KEY_USAGE_OID);
  if (!ext) return undefined;
  const asn = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView.slice().buffer as ArrayBuffer);
  if (asn.offset === -1 || !(asn.result instanceof asn1js.BitString)) {
    throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, 'Cannot decode keyUsage extension');
  }
  const bytes = asn.result.valueBlock.valueHexView;
  const byte = bytes[bit >> 3] ?? 0;
  return (byte & (0x80 >> (bit & 7))) !== 0;
}

const SHORT_NAMES: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
};

/** Approximate RFC 2253 subject, for fault strings only (never compared). */
export function subjectString(cert: pkijs.Certificate): string {
  return [...cert.subject.typesAndValues]
    .reverse()
    .map((tv) => `${SHORT_NAMES[tv.type] ?? tv.type}=${String(tv.value.valueBlock.value ?? '')}`)
    .join(',');
}
