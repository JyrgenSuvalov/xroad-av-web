/**
 * Digest algorithms by XML-DSig URI: the port of X-Road's DigestAlgorithm
 * (common-core/.../crypto/identifier/DigestAlgorithm.java) and
 * Digests.calculateDigest.
 *
 *   DIGEST_URIS                    - the known URIs
 *   isKnownDigestUri(uri)          - DigestAlgorithm.ofUri(uri) is a KnownDigestAlgorithm
 *   await digest(uri, bytes)       - Digests.calculateDigest(DigestAlgorithm.ofUri(uri), bytes)
 *
 * Fault codes:
 *   internal_error - unknown algorithm URI (Java: CryptoException from
 *                    UnknownDigestAlgorithm.name()), or an algorithm WebCrypto
 *                    lacks: MD5 and SHA-224 are known to Java but not ported
 *                    (documented deviation; X-Road uses SHA-512 in practice).
 */
import { XMLDSIG_DIGESTS } from '../trust/crypto';
import { CodedError, ErrorCodes } from '../util/errors';

export const DIGEST_URIS = {
  MD5: 'http://www.w3.org/2001/04/xmldsig-more#md5',
  SHA1: 'http://www.w3.org/2000/09/xmldsig#sha1',
  SHA224: 'http://www.w3.org/2001/04/xmldsig-more#sha224',
  SHA256: 'http://www.w3.org/2001/04/xmlenc#sha256',
  SHA384: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
  SHA512: 'http://www.w3.org/2001/04/xmlenc#sha512',
} as const;

/** URI → WebCrypto name (SHA-1/256/384/512), shared with globalconf and xades. */
const WEBCRYPTO: Readonly<Record<string, string>> = XMLDSIG_DIGESTS;

const KNOWN: ReadonlySet<string> = new Set(Object.values(DIGEST_URIS));

export function isKnownDigestUri(uri: string): boolean {
  return KNOWN.has(uri);
}

/** WebCrypto name for a digest URI, or undefined if not supported. */
export function webCryptoDigestName(uri: string): string | undefined {
  return WEBCRYPTO[uri];
}

export async function digest(uri: string, data: Uint8Array): Promise<Uint8Array> {
  const name = WEBCRYPTO[uri];
  if (!name) {
    throw new CodedError(
      ErrorCodes.X_INTERNAL_ERROR,
      KNOWN.has(uri)
        ? `Digest algorithm not supported by this verifier: ${uri}`
        : `Unknown digest algorithm name for uri: ${uri}`,
    );
  }
  return new Uint8Array(await globalThis.crypto.subtle.digest(name, data as BufferSource));
}
