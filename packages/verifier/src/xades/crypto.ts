/**
 * XML-DSig SignatureMethod verification with WebCrypto.
 *
 *   SIGNATURE_METHODS                                          - supported SignatureMethod URIs
 * RSA PKCS#1 v1.5 (rsa-sha1/256/384/512), RSA-PSS (sha256/384/512-rsa-MGF1,
 * salt length = hash length, UNCONFIRMED: not exercised against the jar) and ECDSA
 * (ecdsa-sha256/384/512; the XML-DSig SignatureValue is raw r‖s, which is
 * WebCrypto's format). Real X-Road containers use rsa-sha512.
 *   await importVerificationKey(uri, cert) → VerificationKey   (Signature.initVerify)
 *   await verifyWithKey(key, data, signatureValue) → boolean      (Signature.verify)
 *
 * Fault codes (Santuario XMLSignatureException inside checkSignatureValue, uncoded
 * in X-Road → internal_error):
 *   internal_error  the certificate key does not fit the algorithm (InvalidKeyException)
 *   internal_error  RSA: signature length ≠ modulus length (SunRsaSign "Bad signature length";
 *                   UNCONFIRMED for RSA-PSS)
 *   internal_error  ECDSA: empty SignatureValue (ArrayIndexOutOfBounds in convertXMLDSIGtoASN1)
 * ECDSA r‖s follows Santuario ECDSAUtils.convertXMLDSIGtoASN1: split at len/2 (an odd
 * last byte is ignored) and leading zeros are allowed, so shorter halves are left-padded
 * for WebCrypto. A half longer than the curve size → false.
 */
import type * as pkijs from 'pkijs';
import { EC_CURVES, HASH_LEN, XMLDSIG_SIGNATURE_METHODS, type XmlDsigSignatureAlg } from '../trust/crypto';
import { CodedError, ErrorCodes } from '../util/errors';

type SigAlg = XmlDsigSignatureAlg;

/** The SignatureMethod table is shared with globalconf (src/trust/crypto.ts). */
export const SIGNATURE_METHODS = XMLDSIG_SIGNATURE_METHODS;

const buf = (b: Uint8Array): ArrayBuffer => b.slice().buffer as ArrayBuffer;

export interface VerificationKey {
  alg: SigAlg;
  key: CryptoKey;
  /** RSA modulus length or ECDSA field size, in bytes. */
  size: number;
}

const internal = (msg: string) => new CodedError(ErrorCodes.X_INTERNAL_ERROR, msg);

export async function importVerificationKey(uri: string, cert: pkijs.Certificate): Promise<VerificationKey> {
  const alg = SIGNATURE_METHODS[uri];
  if (!alg) throw internal(`Unsupported signature method ${uri}`);
  const subtle = globalThis.crypto.subtle;
  const spkiInfo = cert.subjectPublicKeyInfo;
  const spki = buf(new Uint8Array(spkiInfo.toSchema().toBER(false)));
  try {
    if (alg.kind === 'ECDSA') {
      const params = spkiInfo.algorithm.algorithmParams as { valueBlock?: { toString(): string } } | undefined;
      const curve = params?.valueBlock && EC_CURVES[params.valueBlock.toString()];
      if (!curve) throw new Error('not an EC key on a supported named curve');
      const key = await subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: curve.name }, false, ['verify']);
      return { alg, key, size: curve.size };
    }
    const key = await subtle.importKey('spki', spki, { name: alg.kind, hash: alg.hash }, false, ['verify']);
    return { alg, key, size: Math.ceil(((key.algorithm as KeyAlgorithm & { modulusLength?: number }).modulusLength ?? 0) / 8) };
  } catch (e) {
    throw internal(`XMLSignatureException: InvalidKeyException: ${e instanceof Error ? e.message : String(e)}`);
  }
}

export async function verifyWithKey(vk: VerificationKey, data: Uint8Array, signatureValue: Uint8Array): Promise<boolean> {
  const subtle = globalThis.crypto.subtle;
  const { alg, key, size } = vk;
  if (alg.kind === 'ECDSA') {
    if (signatureValue.length === 0) throw internal('ArrayIndexOutOfBoundsException: empty ECDSA SignatureValue');
    const half = signatureValue.length >> 1;
    if (half > size) return false;
    const raw = new Uint8Array(2 * size);
    raw.set(signatureValue.subarray(0, half), size - half);
    raw.set(signatureValue.subarray(half, 2 * half), 2 * size - half);
    return subtle.verify({ name: 'ECDSA', hash: alg.hash }, key, buf(raw), buf(data)).catch(() => false);
  }
  if (signatureValue.length !== size) {
    throw internal(`XMLSignatureException: SignatureException: Bad signature length: got ${signatureValue.length} but was expecting ${size}`);
  }
  const params = alg.kind === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: HASH_LEN[alg.hash] } : { name: alg.kind };
  return subtle.verify(params, key, buf(signatureValue), buf(data)).catch(() => false);
}
