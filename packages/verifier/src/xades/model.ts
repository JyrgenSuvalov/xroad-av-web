/**
 * ds:Signature structure: what Santuario 4.0.4 checks in
 * `new XMLSignature(element, null)` (secure validation on), plus the lazy
 * Reference construction (`SignedInfo.item(i)`). SANTUARIO-RULES.md §1–§3.
 *
 *   readSignatureModel(signatureEl) → SignatureModel   (cached per element)
 *   checkSignatureElement(signatureEl)                 - the signature-doc hook (SignatureHooks)
 *   referenceAt(model, i) → ReferenceModel             - Reference ctor checks, cached
 *
 * Construction fault codes, in Santuario's order (X-Road Signature ctor:
 * XMLSignatureException → malformed_signature, anything else → internal_error):
 *   malformed_signature  the element is not {ds}Signature; first child not ds:SignedInfo
 *   internal_error       SignedInfo has 0 ds:Reference (DOMException) or > 30 (XMLSecurityException)
 *   malformed_signature  SignedInfo children not CanonicalizationMethod, SignatureMethod
 *   internal_error       SignatureMethod rsa-md5 / hmac-md5 (XMLSecurityException)
 *   malformed_signature  any other SignatureMethod we do not know
 *   malformed_signature  next child not ds:SignatureValue; a child after that is neither the first
 *                        ds:KeyInfo nor a ds:Object
 *   internal_error       a *:Manifest directly under ds:Object with 0 or > 30 ds:Reference
 * Not checked at construction (Santuario defers them): the CanonicalizationMethod
 * URI and the SignatureValue content (signature-value.ts), the KeyInfo content
 * (cert.ts) and the References (referenceAt).
 *
 * referenceAt (Reference ctor, XMLSecurityException that is not an XMLSignatureException):
 *   internal_error       ds:Transforms with 0 or > 5 ds:Transform; no ds:DigestMethod or
 *                        ds:DigestValue in place
 *
 * Port deviation: SignatureMethods that Santuario knows but WebCrypto does not
 * cover (DSA, HMAC, rsa-sha224, ripemd160, sha3, ecdsa-sha1/224, EdDSA) are
 * malformed_signature at construction. Java would accept them and verify.
 */
import { CodedError, ErrorCodes } from '../util/errors';
import { childElements, type XElement } from '../xml/safe';
import { SIGNATURE_METHODS } from './crypto';

export const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
export const MAX_REFERENCES = 30;
export const MAX_TRANSFORMS = 5;
/** SignatureMethods refused with secure validation (plain XMLSecurityException). */
export const FORBIDDEN_SIGNATURE_METHODS: ReadonlySet<string> = new Set([
  'http://www.w3.org/2001/04/xmldsig-more#rsa-md5',
  'http://www.w3.org/2001/04/xmldsig-more#hmac-md5',
]);

export interface ReferenceModel {
  element: XElement;
  /** URI attribute value; null when absent. */
  uri: string | null;
  /** ds:Transform Algorithm URIs, in order. */
  transforms: string[];
  /** DigestMethod Algorithm ('' when absent). */
  digestMethod: string;
  digestValueElement: XElement;
}

export interface SignatureModel {
  element: XElement;
  signedInfo: XElement;
  /** CanonicalizationMethod Algorithm ('' when absent); checked only at verify time. */
  canonicalizationMethod: string;
  signatureMethod: string;
  signatureValueElement: XElement;
  /** null when there is no ds:KeyInfo. */
  keyInfo: XElement | null;
  /** The ds:Reference children of ds:SignedInfo, in document order. */
  referenceElements: XElement[];
}

const malformed = (msg: string) => new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, msg);
const internal = (msg: string) => new CodedError(ErrorCodes.X_INTERNAL_ERROR, msg);

export function isDs(el: XElement | undefined, local: string): el is XElement {
  return !!el && el.namespaceURI === DS_NS && el.localName === local;
}

function expandedName(el: XElement | undefined): string {
  return el ? `{${el.namespaceURI ?? ''}}${el.localName}` : 'nothing';
}

function attr(el: XElement, name: string): string | null {
  return el.hasAttribute(name) ? el.getAttribute(name) : null;
}

function algorithm(el: XElement): string {
  return attr(el, 'Algorithm') ?? '';
}

export function checkSignatureElement(signatureEl: XElement): void {
  readSignatureModel(signatureEl);
}

const models = new WeakMap<XElement, SignatureModel>();
const references = new WeakMap<XElement, ReferenceModel>();

export function readSignatureModel(signatureEl: XElement): SignatureModel {
  const cached = models.get(signatureEl);
  if (cached) return cached;
  if (!isDs(signatureEl, 'Signature')) {
    throw malformed(`Cannot create XMLSignature from ${expandedName(signatureEl)}`);
  }
  const kids = childElements(signatureEl);
  const signedInfo = kids[0];
  if (!isDs(signedInfo, 'SignedInfo')) throw malformed('Cannot find SignedInfo element in Signature');
  const si = readSignedInfo(signedInfo);
  const signatureValueElement = kids[1];
  if (!isDs(signatureValueElement, 'SignatureValue')) {
    throw malformed('Cannot find SignatureValue element in Signature');
  }
  let i = 2;
  const keyInfo = isDs(kids[i], 'KeyInfo') ? kids[i++]! : null;
  for (; i < kids.length; i++) {
    const obj = kids[i]!;
    if (!isDs(obj, 'Object')) {
      throw malformed(`Unexpected element ${expandedName(obj)} in Signature`);
    }
    for (const child of childElements(obj)) if (child.localName === 'Manifest') countReferences(child);
  }
  const model: SignatureModel = { element: signatureEl, signedInfo, ...si, signatureValueElement, keyInfo };
  models.set(signatureEl, model);
  return model;
}

/** Manifest ctor (SignedInfo's superclass runs it first). */
function countReferences(manifest: XElement): XElement[] {
  const refs = childElements(manifest).filter((k) => isDs(k, 'Reference'));
  if (refs.length === 0) {
    throw internal(`DOMException: ${manifest.localName} contains no ds:Reference`);
  }
  if (refs.length > MAX_REFERENCES) {
    throw internal(
      `XMLSecurityException: A maximum of ${MAX_REFERENCES} references per Manifest are allowed with secure validation`,
    );
  }
  return refs;
}

function readSignedInfo(el: XElement) {
  const referenceElements = countReferences(el);
  const kids = childElements(el);
  const c14n = kids[0];
  if (!isDs(c14n, 'CanonicalizationMethod')) throw malformed('Cannot find CanonicalizationMethod in SignedInfo');
  const sm = kids[1];
  if (!isDs(sm, 'SignatureMethod')) throw malformed('Cannot find SignatureMethod in SignedInfo');
  const signatureMethod = algorithm(sm);
  if (FORBIDDEN_SIGNATURE_METHODS.has(signatureMethod)) {
    throw internal(`XMLSecurityException: Signature algorithm ${signatureMethod} is forbidden with secure validation`);
  }
  if (!SIGNATURE_METHODS[signatureMethod]) throw malformed(`Unknown signature algorithm ${signatureMethod}`);
  return { canonicalizationMethod: algorithm(c14n), signatureMethod, referenceElements };
}

export function referenceCount(model: SignatureModel): number {
  return model.referenceElements.length;
}

/** SignedInfo.item(i): the Reference ctor's checks, run once per element. */
export function referenceAt(model: SignatureModel, i: number): ReferenceModel {
  const el = model.referenceElements[i]!;
  const cached = references.get(el);
  if (cached) return cached;
  const kids = childElements(el);
  let k = 0;
  const transforms: string[] = [];
  if (isDs(kids[k], 'Transforms')) {
    for (const t of childElements(kids[k++]!)) if (isDs(t, 'Transform')) transforms.push(algorithm(t));
    if (transforms.length === 0) throw internal('TransformationException: Transforms contains no ds:Transform');
    if (transforms.length > MAX_TRANSFORMS) {
      throw internal(
        `XMLSecurityException: A maximum of ${MAX_TRANSFORMS} transforms per Reference are allowed with secure validation`,
      );
    }
  }
  const dm = kids[k++];
  if (!isDs(dm, 'DigestMethod')) throw internal('XMLSecurityException: Reference has no DigestMethod');
  const dv = kids[k++];
  if (!isDs(dv, 'DigestValue')) throw internal('XMLSecurityException: Reference has no DigestValue');
  const ref: ReferenceModel = {
    element: el,
    uri: attr(el, 'URI'),
    transforms,
    digestMethod: algorithm(dm),
    digestValueElement: dv,
  };
  references.set(el, ref);
  return ref;
}
