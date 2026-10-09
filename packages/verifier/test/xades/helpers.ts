// Hand-made ds:Signature documents, signed with a throwaway WebCrypto key over
// our own C14N of ds:SignedInfo.
import * as pkijs from 'pkijs';
import { C14N_10, canonicalize } from '../../src/c14n/c14n';
import { encodeBase64, encodeUtf8 } from '../../src/util/bytes';
import { DIGEST_URIS } from '../../src/hashchain/digest';
import { firstElementByTagName, parseXml } from '../../src/xml/safe';
import { loadSignatureDocument, type SignatureDocument } from '../../src/xml/signature-doc';
import type { SigningCertificate } from '../../src/xades/cert';
import { hooks } from './pipeline';

export const SHA512 = DIGEST_URIS.SHA512;
export const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
export const ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
export const b64 = encodeBase64;

export async function sha512(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? encodeUtf8(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-512', bytes as BufferSource));
}

export interface RefOpts {
  digestMethod?: string;
  transforms?: string[];
  /** Raw Reference children, replacing the generated ones. */
  body?: string;
}

export function ref(uri: string | null, digestValue: Uint8Array | string, opts: RefOpts = {}): string {
  const uriAttr = uri === null ? '' : ` URI="${uri}"`;
  const dv = typeof digestValue === 'string' ? digestValue : b64(digestValue);
  const tr = opts.transforms
    ? `<ds:Transforms>${opts.transforms.map((t) => `<ds:Transform Algorithm="${t}"/>`).join('')}</ds:Transforms>`
    : '';
  const body =
    opts.body ??
    `${tr}<ds:DigestMethod Algorithm="${opts.digestMethod ?? SHA512}"/><ds:DigestValue>${dv}</ds:DigestValue>`;
  return `<ds:Reference${uriAttr}>${body}</ds:Reference>`;
}

export interface SigOpts {
  refs: string[];
  c14n?: string;
  signatureMethod?: string;
  /** SignatureValue text; '__SIG__' is replaced by sign(). */
  signatureValue?: string;
  /** Whole ds:KeyInfo element (or anything placed after SignatureValue); default none. */
  keyInfo?: string;
  /** Default: a ds:Object holding xades:SignedProperties Id="signed-properties". */
  objects?: string;
}

export const SIGNED_PROPERTIES =
  '<ds:Object><xades:QualifyingProperties><xades:SignedProperties Id="signed-properties">' +
  '<xades:SigningTime>2026-10-06T12:00:00Z</xades:SigningTime></xades:SignedProperties>' +
  '</xades:QualifyingProperties></ds:Object>';

export function signatureXml(o: SigOpts): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" ' +
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">' +
    '<ds:Signature Id="signature"><ds:SignedInfo>' +
    `<ds:CanonicalizationMethod Algorithm="${o.c14n ?? C14N_10}"/>` +
    `<ds:SignatureMethod Algorithm="${o.signatureMethod ?? RSA_SHA512}"/>` +
    o.refs.join('') +
    `</ds:SignedInfo><ds:SignatureValue>${o.signatureValue ?? '__SIG__'}</ds:SignatureValue>` +
    (o.keyInfo ?? '') +
    (o.objects ?? SIGNED_PROPERTIES) +
    '</ds:Signature></asic:XAdESSignatures>'
  );
}

/** Digest of the element with Id=id in an (unsigned) document: inclusive C14N, as IdResolver does. */
export async function digestOfId(xml: string, id: string): Promise<Uint8Array> {
  const doc = parseXml(xml);
  const all = doc.getElementsByTagName('*');
  for (let i = 0; i < all.length; i++) {
    const el = all.item(i)!;
    if (el.getAttribute('Id') === id) return sha512(canonicalize(el));
  }
  throw new Error(`no Id=${id}`);
}

export interface TestKey {
  privateKey: CryptoKey;
  signing: SigningCertificate;
  alg: 'RSA' | 'EC';
}

/** A key pair plus a certificate object that carries only the public key (all verifySignatureValue reads). */
export async function makeKey(alg: 'RSA' | 'EC' = 'RSA'): Promise<TestKey> {
  const params =
    alg === 'RSA'
      ? { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-512' }
      : { name: 'ECDSA', namedCurve: 'P-256' };
  const pair = (await crypto.subtle.generateKey(params, true, ['sign', 'verify'])) as CryptoKeyPair;
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
  const cert = new pkijs.Certificate();
  cert.subjectPublicKeyInfo = pkijs.PublicKeyInfo.fromBER(spki);
  return { privateKey: pair.privateKey, signing: { der: new Uint8Array(), cert }, alg };
}

/** Signs C14N(SignedInfo) and puts the base64 value where '__SIG__' is. */
export async function sign(xml: string, key: TestKey): Promise<string> {
  const si = firstElementByTagName(parseXml(xml), 'ds:SignedInfo')!;
  const data = canonicalize(si) as BufferSource;
  const sig =
    key.alg === 'RSA'
      ? await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key.privateKey, data)
      : await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, data);
  return xml.replace('__SIG__', b64(new Uint8Array(sig)));
}

export function load(xml: string): SignatureDocument {
  return loadSignatureDocument(xml, hooks);
}
