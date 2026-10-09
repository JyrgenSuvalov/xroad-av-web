/**
 * Signature.getOcspResponses (SIG:307-330) and Helper.getEncapsulatedOCSPValueElements
 * (HLP:190-216): every xades:EncapsulatedOCSPValue found by the namespace-aware
 * child path
 *   xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/
 *   xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue
 * under the signature's FIRST ds:Object (SignatureDocument.object).
 *
 *   getOcspResponses(object) → OcspResp[]
 *     none                    → malformed_signature "Could not get any OCSP elements from signature"
 *     base64/DER not an OCSPResponse → malformed_signature (Java: CodedException(X_MALFORMED_SIGNATURE, IOException))
 */
import { CodedError, ErrorCodes } from '../util/errors';
import { decodeBase64Lenient } from '../util/bytes';
import { childElements, textContent, type XElement } from '../xml/safe';
import { OcspParseError, parseOcspResp, type OcspResp } from './parse';

export const XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#';

/** Namespace-aware XPath of child steps in the xades namespace, relative to `context`. */
export function xadesChildPath(context: XElement, steps: readonly string[]): XElement[] {
  let level: XElement[] = [context];
  for (const step of steps) {
    level = level.flatMap((el) =>
      childElements(el).filter((c) => c.namespaceURI === XADES_NS && c.localName === step),
    );
  }
  return level;
}

const OCSP_PATH = [
  'QualifyingProperties',
  'UnsignedProperties',
  'UnsignedSignatureProperties',
  'RevocationValues',
  'OCSPValues',
  'EncapsulatedOCSPValue',
] as const;

export function getOcspResponses(object: XElement): OcspResp[] {
  const elements = xadesChildPath(object, OCSP_PATH);
  if (elements.length === 0) {
    throw new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, 'Could not get any OCSP elements from signature');
  }
  return elements.map((el) => {
    try {
      return parseOcspResp(decodeBase64Lenient(textContent(el)));
    } catch (e) {
      const msg = e instanceof OcspParseError || e instanceof Error ? e.message : String(e);
      throw new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, msg, { cause: e });
    }
  });
}
