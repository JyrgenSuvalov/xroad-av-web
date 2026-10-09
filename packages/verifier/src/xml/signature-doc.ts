/**
 * Port of the parsing part of `new Signature(xml)` (SIG:104-123)
 * and `getSignatureTimestamp()` (SIG:225-230).
 *
 *   loadSignatureDocument(xml, hooks?) → SignatureDocument
 *     1. parse UTF-8 bytes of xml (DOCTYPE/not well-formed → invalid_xml)
 *     2. first element with qualified name `ds:Signature`, else malformed_signature
 *     3. hooks.checkSignatureElement(el) - Santuario XMLSignature structure
 *        checks; supplied by src/xades (must throw CodedError)
 *     4. first `ds:Object`, else malformed_signature
 *   getSignatureTimestamp(doc) → text of the first `xades:EncapsulatedTimeStamp`,
 *     else of the first `xades:SignatureTimeStamp`, else malformed_signature.
 */
import { CodedError, ErrorCodes } from '../util/errors';
import { firstElementByTagName, parseXml, type XDocument, type XElement } from './safe';

export interface SignatureDocument {
  doc: XDocument;
  signature: XElement;
  object: XElement;
}

export interface SignatureHooks {
  checkSignatureElement?: (signature: XElement) => void;
}

export function elementNotFound(tag: string): CodedError {
  return new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, `Could not find element "${tag}"`);
}

export function loadSignatureDocument(xml: string, hooks: SignatureHooks = {}): SignatureDocument {
  const doc = parseXml(xml, ErrorCodes.X_INVALID_XML);
  const signature = firstElementByTagName(doc, 'ds:Signature');
  if (!signature) throw elementNotFound('ds:Signature');
  hooks.checkSignatureElement?.(signature);
  const object = firstElementByTagName(doc, 'ds:Object');
  if (!object) throw elementNotFound('ds:Object');
  return { doc, signature, object };
}

export function getSignatureTimestamp(sd: SignatureDocument): string {
  const el =
    firstElementByTagName(sd.doc, 'xades:EncapsulatedTimeStamp') ??
    firstElementByTagName(sd.doc, 'xades:SignatureTimeStamp');
  if (!el) throw elementNotFound('xades:EncapsulatedTimeStamp');
  return el.textContent ?? '';
}
