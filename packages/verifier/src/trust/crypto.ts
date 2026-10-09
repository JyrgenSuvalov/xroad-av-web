/**
 * OID-based digests and signature verification over WebCrypto, for CMS
 * (timestamp SignerInfo) and, later, OCSP BasicOCSPResponse.
 *
 *   digestByOid(oid, data)                         - throws UnsupportedAlgorithmError
 *   hashForDigestOid(oid)                          - WebCrypto name or null
 *   verifyByOid({ cert, signatureAlgorithm, digestAlgorithm?, data, signature })
 *       → boolean; throws UnsupportedAlgorithmError for algorithms WebCrypto
 *         cannot do (callers map that to their Java-equivalent fault).
 *   sha1(data)
 *
 * Shared algorithm tables (also used by globalconf/crypto and xades/crypto,
 * which verify by XML-DSig URI rather than by OID):
 *   XMLDSIG_DIGESTS            - DigestMethod URI → WebCrypto hash
 *   XMLDSIG_SIGNATURE_METHODS  - SignatureMethod URI → { kind, hash }
 *   HASH_LEN, EC_CURVES, ecdsaDerToRaw(der, size)
 *
 * Supported: SHA-1/256/384/512 digests; RSA PKCS#1 v1.5 (rsaEncryption + digest,
 * or shaNWithRSAEncryption), RSASSA-PSS (MGF1 with the same hash), ECDSA P-256/384/521.
 * Not supported (BC would accept): SHA-224, SHA-3, RIPEMD, MD5, DSA, EdDSA, GOST.
 */

import * as asn1js from 'asn1js';
import type * as pkijs from 'pkijs';
import { primitiveBytes } from './der';

export type Hash = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

export const HASH_LEN: Readonly<Record<Hash, number>> = { 'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 };

/** XML-DSig DigestMethod URIs that WebCrypto can compute. */
export const XMLDSIG_DIGESTS: Readonly<Record<string, Hash>> = {
  'http://www.w3.org/2000/09/xmldsig#sha1': 'SHA-1',
  'http://www.w3.org/2001/04/xmlenc#sha256': 'SHA-256',
  'http://www.w3.org/2001/04/xmldsig-more#sha384': 'SHA-384',
  'http://www.w3.org/2001/04/xmlenc#sha512': 'SHA-512',
};

export type XmlDsigSignatureAlg = { kind: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'ECDSA'; hash: Hash };

/**
 * XML-DSig SignatureMethod URIs. RSA-PSS uses the Santuario URIs with salt
 * length = hash length (UNCONFIRMED: not exercised against the jar).
 */
export const XMLDSIG_SIGNATURE_METHODS: Readonly<Record<string, XmlDsigSignatureAlg>> = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': { kind: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': { kind: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384': { kind: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': { kind: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1': { kind: 'RSA-PSS', hash: 'SHA-256' },
  'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1': { kind: 'RSA-PSS', hash: 'SHA-384' },
  'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1': { kind: 'RSA-PSS', hash: 'SHA-512' },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256': { kind: 'ECDSA', hash: 'SHA-256' },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384': { kind: 'ECDSA', hash: 'SHA-384' },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512': { kind: 'ECDSA', hash: 'SHA-512' },
};

export class UnsupportedAlgorithmError extends Error {
  constructor(what: string) {
    super(`unsupported algorithm: ${what}`);
    this.name = 'UnsupportedAlgorithmError';
  }
}

export const OID = {
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsaPss: '1.2.840.113549.1.1.10',
  mgf1: '1.2.840.113549.1.1.8',
  ecPublicKey: '1.2.840.10045.2.1',
} as const;

const DIGEST_OIDS: Record<string, Hash> = {
  [OID.sha1]: 'SHA-1',
  [OID.sha256]: 'SHA-256',
  [OID.sha384]: 'SHA-384',
  [OID.sha512]: 'SHA-512',
};

const RSA_SIG_OIDS: Record<string, Hash> = {
  '1.2.840.113549.1.1.5': 'SHA-1',
  '1.2.840.113549.1.1.11': 'SHA-256',
  '1.2.840.113549.1.1.12': 'SHA-384',
  '1.2.840.113549.1.1.13': 'SHA-512',
};

const ECDSA_SIG_OIDS: Record<string, Hash> = {
  '1.2.840.10045.4.1': 'SHA-1',
  '1.2.840.10045.4.3.2': 'SHA-256',
  '1.2.840.10045.4.3.3': 'SHA-384',
  '1.2.840.10045.4.3.4': 'SHA-512',
};

/** Named-curve OID → WebCrypto curve name and field size in bytes. */
export const EC_CURVES: Readonly<Record<string, { name: string; size: number }>> = {
  '1.2.840.10045.3.1.7': { name: 'P-256', size: 32 },
  '1.3.132.0.34': { name: 'P-384', size: 48 },
  '1.3.132.0.35': { name: 'P-521', size: 66 },
};

const subtle = () => globalThis.crypto.subtle;
const bs = (b: Uint8Array) => b as BufferSource;

export function hashForDigestOid(oid: string): Hash | null {
  return DIGEST_OIDS[oid] ?? null;
}

export async function digestByOid(oid: string, data: Uint8Array): Promise<Uint8Array> {
  const h = hashForDigestOid(oid);
  if (!h) throw new UnsupportedAlgorithmError(`digest ${oid}`);
  return new Uint8Array(await subtle().digest(h, bs(data)));
}

export async function sha1(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest('SHA-1', bs(data)));
}

export interface VerifyByOidInput {
  cert: pkijs.Certificate;
  signatureAlgorithm: pkijs.AlgorithmIdentifier;
  /** Needed when signatureAlgorithm is bare rsaEncryption / id-ecPublicKey (CMS SignerInfo). */
  digestAlgorithm?: pkijs.AlgorithmIdentifier;
  data: Uint8Array;
  signature: Uint8Array;
}

export async function verifyByOid(input: VerifyByOidInput): Promise<boolean> {
  const sigOid = input.signatureAlgorithm.algorithmId;
  const digestHash = () => {
    const oid = input.digestAlgorithm?.algorithmId;
    const h = oid ? hashForDigestOid(oid) : null;
    if (!h) throw new UnsupportedAlgorithmError(`digest ${oid ?? '(none)'} for ${sigOid}`);
    return h;
  };
  const spkiInfo = input.cert.subjectPublicKeyInfo;
  const spki = bs(new Uint8Array(spkiInfo.toSchema().toBER(false)));

  let rsaHash: Hash | undefined;
  if (sigOid === OID.rsaEncryption) rsaHash = digestHash();
  else rsaHash = RSA_SIG_OIDS[sigOid];
  if (rsaHash) {
    const key = await importOrNull(spki, { name: 'RSASSA-PKCS1-v1_5', hash: rsaHash });
    if (!key) return false;
    return subtle().verify({ name: 'RSASSA-PKCS1-v1_5' }, key, bs(input.signature), bs(input.data));
  }

  if (sigOid === OID.rsaPss) {
    const { hash, saltLength } = pssParams(input.signatureAlgorithm);
    const key = await importOrNull(spki, { name: 'RSA-PSS', hash });
    if (!key) return false;
    return subtle().verify({ name: 'RSA-PSS', saltLength }, key, bs(input.signature), bs(input.data));
  }

  const ecHash = sigOid === OID.ecPublicKey ? digestHash() : ECDSA_SIG_OIDS[sigOid];
  if (ecHash) {
    const params = spkiInfo.algorithm.algorithmParams as asn1js.ObjectIdentifier | undefined;
    const curve = params instanceof asn1js.ObjectIdentifier ? EC_CURVES[params.valueBlock.toString()] : undefined;
    if (!curve) return false; // not an EC key on a supported curve: BC fails to verify too
    const key = await importOrNull(spki, { name: 'ECDSA', namedCurve: curve.name });
    if (!key) return false;
    const raw = ecdsaDerToRaw(input.signature, curve.size);
    if (!raw) return false;
    return subtle().verify({ name: 'ECDSA', hash: ecHash }, key, bs(raw), bs(input.data));
  }

  throw new UnsupportedAlgorithmError(`signature ${sigOid}`);
}

async function importOrNull(spki: BufferSource, alg: RsaHashedImportParams | EcKeyImportParams): Promise<CryptoKey | null> {
  try {
    return await subtle().importKey('spki', spki, alg, false, ['verify']);
  } catch {
    return null; // key type does not match the algorithm
  }
}

/** RSASSA-PSS-params; WebCrypto needs MGF1 over the same hash and trailerField 1. */
function pssParams(alg: pkijs.AlgorithmIdentifier): { hash: Hash; saltLength: number } {
  let hash: Hash = 'SHA-1';
  let mgfHash: Hash = 'SHA-1';
  let saltLength = 20;
  const p = alg.algorithmParams;
  if (p instanceof asn1js.Sequence) {
    for (const field of p.valueBlock.value) {
      if (field.idBlock.tagClass !== 3) continue;
      const inner = (field.valueBlock as unknown as { value: asn1js.AsnType[] }).value?.[0];
      if (!inner) continue;
      switch (field.idBlock.tagNumber) {
        case 0: {
          const oid = algOid(inner);
          const h = oid ? hashForDigestOid(oid) : null;
          if (!h) throw new UnsupportedAlgorithmError(`PSS hash ${oid}`);
          hash = h;
          break;
        }
        case 1: {
          const oid = algOid(inner);
          if (oid !== OID.mgf1 || !(inner instanceof asn1js.Sequence)) throw new UnsupportedAlgorithmError(`PSS MGF ${oid}`);
          const hOid = algOid(inner.valueBlock.value[1]);
          const h = hOid ? hashForDigestOid(hOid) : null;
          if (!h) throw new UnsupportedAlgorithmError(`MGF1 hash ${hOid}`);
          mgfHash = h;
          break;
        }
        case 2:
          if (inner instanceof asn1js.Integer) saltLength = Number(inner.toBigInt());
          break;
        case 3:
          if (inner instanceof asn1js.Integer && inner.toBigInt() !== 1n) throw new UnsupportedAlgorithmError('PSS trailerField');
          break;
      }
    }
  }
  if (mgfHash !== hash) throw new UnsupportedAlgorithmError('PSS with MGF1 hash != message hash');
  return { hash, saltLength };
}

function algOid(el: asn1js.AsnType | undefined): string | null {
  if (!(el instanceof asn1js.Sequence)) return null;
  const oid = el.valueBlock.value[0];
  return oid instanceof asn1js.ObjectIdentifier ? oid.valueBlock.toString() : null;
}

/** ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } → r‖s, each `size` bytes. */
export function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array | null {
  const parsed = asn1js.fromBER(der);
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) return null;
  const [r, s] = parsed.result.valueBlock.value;
  if (!(r instanceof asn1js.Integer) || !(s instanceof asn1js.Integer)) return null;
  const out = new Uint8Array(size * 2);
  for (const [i, n] of [r, s].entries()) {
    let v = primitiveBytes(n);
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    if (v.length > size) return null;
    out.set(v, i * size + (size - v.length));
  }
  return out;
}
