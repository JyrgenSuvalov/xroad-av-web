// Algorithm URIs, certificate decoding and WebCrypto verification.

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import {
  EC_CURVES,
  HASH_LEN,
  type Hash,
  XMLDSIG_DIGESTS,
  XMLDSIG_SIGNATURE_METHODS,
  type XmlDsigSignatureAlg,
  ecdsaDerToRaw,
} from '../trust/crypto';
import { arrayBufferCopy as buf, decodeBase64Strict, latin1 } from '../util/bytes';
import { GlobalConfError } from './errors';

// Algorithm tables and the ECDSA DER → r‖s conversion are shared with
// src/trust/crypto.ts (RSA-PSS and sha384 UNCONFIRMED in repo).
type SigAlg = XmlDsigSignatureAlg;

const subtle = () => globalThis.crypto.subtle;

export function digestAlgorithm(uri: string): Hash {
  const h = XMLDSIG_DIGESTS[uri];
  if (!h) throw new GlobalConfError('UNSUPPORTED_ALGORITHM', `digest algorithm ${uri}`);
  return h;
}

export async function digest(uri: string, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest(digestAlgorithm(uri), buf(data)));
}

export function signatureAlgorithm(uri: string): SigAlg {
  const a = XMLDSIG_SIGNATURE_METHODS[uri];
  if (!a) throw new GlobalConfError('UNSUPPORTED_ALGORITHM', `signature algorithm ${uri}`);
  return a;
}

/**
 * Decode a certificate field. Anchor certs are base64(DER); shared-params
 * some instances publish certs as base64(PEM text). Accepts both, plus raw DER bytes.
 */
export function certificateDer(bytes: Uint8Array): Uint8Array | null {
  const head = latin1(bytes.subarray(0, 64)).trimStart();
  if (!head.startsWith('-----BEGIN')) return bytes;
  const pem = latin1(bytes);
  const m = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/.exec(pem);
  return m ? decodeBase64Strict(m[1]!) : null;
}

export function parseCertificate(der: Uint8Array): pkijs.Certificate {
  return pkijs.Certificate.fromBER(buf(der));
}

/** Throws `onError` if `text` is not base64 of a DER or PEM certificate. */
export function decodeCertField(
  text: string,
  onError: (msg: string) => GlobalConfError,
): { der: Uint8Array; cert: pkijs.Certificate } {
  const raw = decodeBase64Strict(text);
  const der = raw && certificateDer(raw);
  if (!der || der.length === 0) throw onError('certificate is not base64 DER/PEM');
  try {
    return { der, cert: parseCertificate(der) };
  } catch (e) {
    throw onError(`certificate does not parse: ${String(e)}`);
  }
}

export function certValidAt(cert: pkijs.Certificate, now: Date): boolean {
  return cert.notBefore.value <= now && now <= cert.notAfter.value;
}

/** Verify a signature with the certificate's public key via WebCrypto. */
export async function verifySignature(
  algorithmUri: string,
  cert: pkijs.Certificate,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const alg = signatureAlgorithm(algorithmUri);
  const spkiInfo = cert.subjectPublicKeyInfo;
  const spki = buf(new Uint8Array(spkiInfo.toSchema().toBER(false)));
  try {
    if (alg.kind === 'ECDSA') {
      const params = spkiInfo.algorithm.algorithmParams as asn1js.ObjectIdentifier | undefined;
      const curve = params && EC_CURVES[params.valueBlock.toString()];
      if (!curve) throw new GlobalConfError('UNSUPPORTED_ALGORITHM', 'unsupported EC curve');
      const key = await subtle().importKey('spki', spki, { name: 'ECDSA', namedCurve: curve.name }, false, ['verify']);
      const raw = ecdsaDerToRaw(signature, curve.size);
      if (!raw) return false;
      return await subtle().verify({ name: 'ECDSA', hash: alg.hash }, key, buf(raw), buf(data));
    }
    const key = await subtle().importKey('spki', spki, { name: alg.kind, hash: alg.hash }, false, ['verify']);
    const params =
      alg.kind === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: HASH_LEN[alg.hash] } : { name: alg.kind };
    return await subtle().verify(params, key, buf(signature), buf(data));
  } catch (e) {
    if (e instanceof GlobalConfError) throw e;
    // Key type does not match the algorithm, or the key does not import.
    return false;
  }
}
