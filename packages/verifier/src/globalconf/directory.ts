// Signed configuration directory: MIME split, signature check against the anchor, inner parts.

import type { ConfigurationAnchor } from './anchor';
import { anchorCerts } from './anchor';
import { bytesEqual, decodeBase64Strict } from '../util/bytes';
import { certValidAt, digest, digestAlgorithm, parseCertificate, signatureAlgorithm, verifySignature } from './crypto';
import { GlobalConfError } from './errors';
import { type Headers, boundaryOf, splitEntity, splitMultipart } from './mime';

export const SHARED_PARAMETERS = 'SHARED-PARAMETERS';
export const PRIVATE_PARAMETERS = 'PRIVATE-PARAMETERS';
export const NEXTUPDATE = 'NEXTUPDATE';

export interface DirectoryPart {
  /** e.g. SHARED-PARAMETERS; undefined when the part has no Content-identifier. */
  contentIdentifier?: string;
  instance?: string;
  /** Host-absolute path on the central server, e.g. /V6/<ts>/shared-params.xml. */
  contentLocation: string;
  hashAlgorithmId: string;
  hash: Uint8Array;
}

export interface VerifiedDirectory {
  /** `Version` header (2 when absent). */
  version: number;
  /** `Expire-date` exactly as published. */
  expireDateText: string;
  expireDate: Date;
  signatureAlgorithmId: string;
  parts: DirectoryPart[];
  sharedParams: DirectoryPart;
  nextUpdate?: DirectoryPart;
}

export interface VerifyDirectoryOptions {
  /** Clock for the verification-cert validity check. Default: new Date(). */
  now?: Date;
  /** Reject when the `Version` header differs (browser guard). */
  expectedVersion?: number;
}

const malformed = (msg: string) => new GlobalConfError('DIRECTORY_MALFORMED', msg);
const sigMalformed = (msg: string) => new GlobalConfError('SIGNATURE_MALFORMED', msg);

/**
 * Verify the raw directory bytes against the anchor and parse the inner
 * directory. Throws GlobalConfError. Expiry is NOT enforced here
 * (expired is amber, not a rejection); callers compare `expireDate` to their clock.
 */
export async function verifyDirectory(
  raw: Uint8Array,
  anchor: ConfigurationAnchor,
  options: VerifyDirectoryOptions = {},
): Promise<VerifiedDirectory> {
  const now = options.now ?? new Date();

  // Outer split. The body carries its own Content-Type header line.
  const outer = splitEntity(raw);
  const outerBoundary = boundaryOf(outer.headers.get('content-type') ?? '', 'multipart/related');
  const outerParts = splitMultipart(raw, outerBoundary, outer.bodyStart);
  if (outerParts.length !== 2) throw malformed(`expected 2 outer parts, got ${outerParts.length}`);
  const [signedPart, sigPart] = outerParts as [(typeof outerParts)[0], (typeof outerParts)[0]];

  // Signed bytes = part 1 body, sliced from the original buffer.
  const innerBoundary = boundaryOf(signedPart.headers.get('content-type') ?? '', 'multipart/mixed');
  const signedBytes = raw.subarray(signedPart.bodyStart, signedPart.bodyEnd);

  // Signature part.
  const sh = sigPart.headers;
  if (sh.get('content-type') !== 'application/octet-stream') throw sigMalformed('signature Content-Type');
  if (sh.get('content-transfer-encoding') !== 'base64') throw sigMalformed('signature Content-Transfer-Encoding');
  const sigAlgId = sh.get('signature-algorithm-id');
  if (!sigAlgId) throw sigMalformed('Signature-Algorithm-Id missing');
  const certHashHeader = sh.get('verification-certificate-hash');
  if (!certHashHeader) throw sigMalformed('Verification-certificate-hash missing');
  const { hash: certHash, hashAlgorithmId: certHashAlg } = parseCertHashHeader(certHashHeader);
  const signature = decodeBase64Strict(new TextDecoder().decode(raw.subarray(sigPart.bodyStart, sigPart.bodyEnd)));
  if (!signature || signature.length === 0) throw sigMalformed('signature body is not base64');
  signatureAlgorithm(sigAlgId); // UNSUPPORTED_ALGORITHM before doing any work
  digestAlgorithm(certHashAlg);

  // Select the anchor cert by hash.
  let verificationCert;
  for (const der of anchorCerts(anchor)) {
    if (bytesEqual(await digest(certHashAlg, der), certHash)) {
      verificationCert = parseCertificate(der);
      break;
    }
  }
  if (!verificationCert) {
    throw new GlobalConfError('VERIFICATION_CERT_NOT_FOUND', 'directory not signed by an anchor key');
  }
  if (!certValidAt(verificationCert, now)) {
    throw new GlobalConfError('VERIFICATION_CERT_NOT_FOUND', 'anchor verification certificate is not valid now');
  }

  // Verify.
  if (!(await verifySignature(sigAlgId, verificationCert, signedBytes, signature))) {
    throw new GlobalConfError('SIGNATURE_INVALID', 'directory signature does not verify');
  }

  // Inner multipart, only after the signature verified.
  return parseInner(signedBytes, innerBoundary, anchor.instanceIdentifier, sigAlgId, options.expectedVersion);
}

function parseCertHashHeader(value: string): { hash: Uint8Array; hashAlgorithmId: string } {
  const [first, ...params] = value.split(';');
  const hash = decodeBase64Strict((first ?? '').trim());
  if (!hash || hash.length === 0) throw sigMalformed('Verification-certificate-hash is not base64');
  const hashAlgorithmId = param(params, 'hash-algorithm-id');
  if (!hashAlgorithmId) throw sigMalformed('Verification-certificate-hash: hash-algorithm-id missing');
  return { hash, hashAlgorithmId };
}

/** Look up `name=value` among `;`-separated parameters; strips single or double quotes. */
function param(params: string[], name: string): string | undefined {
  for (const p of params) {
    const i = p.indexOf('=');
    if (i < 0 || p.slice(0, i).trim().toLowerCase() !== name) continue;
    return p.slice(i + 1).trim().replace(/^(['"])(.*)\1$/, '$2');
  }
  return undefined;
}

// Java OffsetDateTime.parse (ISO_OFFSET_DATE_TIME): seconds and fraction optional.
const EXPIRE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/;

export function parseExpireDate(text: string): Date {
  if (!EXPIRE_RE.test(text)) throw malformed(`Expire-date ${JSON.stringify(text)} is not ISO-8601 with offset`);
  // Date.parse handles at most millisecond precision; truncate longer fractions.
  const d = new Date(text.replace(/(\.\d{3})\d+/, '$1'));
  if (Number.isNaN(d.getTime())) throw malformed(`Expire-date ${JSON.stringify(text)} is invalid`);
  return d;
}

// Content-location must be a host-absolute path we can safely prefix with /globalconf.
const LOCATION_RE = /^\/V\d+\/\d+\/[A-Za-z0-9._-]+$/;

export function checkContentLocation(loc: string): void {
  if (!LOCATION_RE.test(loc) || loc.includes('..')) {
    throw malformed(`unsafe Content-location ${JSON.stringify(loc)}`);
  }
}

function parseInner(
  signedBytes: Uint8Array,
  boundary: string,
  instanceIdentifier: string,
  signatureAlgorithmId: string,
  expectedVersion: number | undefined,
): VerifiedDirectory {
  const parts = splitMultipart(signedBytes, boundary);
  const [head, ...content] = parts;
  if (!head) throw malformed('inner directory has no parts');

  const expireDateText = head.headers.get('expire-date');
  if (!expireDateText) throw malformed('Expire-date missing');
  const expireDate = parseExpireDate(expireDateText);

  const versionText = head.headers.get('version');
  let version = 2;
  if (versionText !== undefined) {
    if (!/^\d+$/.test(versionText)) throw malformed(`Version ${JSON.stringify(versionText)}`);
    version = Number(versionText);
  }
  if (expectedVersion !== undefined && version !== expectedVersion) {
    throw malformed(`requested version ${expectedVersion}, directory says ${version}`);
  }

  const dirParts = content.map((p) => contentPart(p.headers, signedBytes.subarray(p.bodyStart, p.bodyEnd), instanceIdentifier));
  const shared = dirParts.filter((p) => p.contentIdentifier === SHARED_PARAMETERS);
  if (shared.length !== 1) throw malformed(`expected exactly one ${SHARED_PARAMETERS} part, got ${shared.length}`);
  const sharedParams = shared[0]!;
  checkContentLocation(sharedParams.contentLocation);
  const nextUpdate = dirParts.find((p) => p.contentIdentifier === NEXTUPDATE);
  if (nextUpdate) checkContentLocation(nextUpdate.contentLocation);

  return {
    version,
    expireDateText,
    expireDate,
    signatureAlgorithmId,
    parts: dirParts,
    sharedParams,
    ...(nextUpdate ? { nextUpdate } : {}),
  };
}

function contentPart(h: Headers, body: Uint8Array, instanceIdentifier: string): DirectoryPart {
  if (h.get('content-type') !== 'application/octet-stream') throw malformed('part Content-type');
  if (h.get('content-transfer-encoding') !== 'base64') throw malformed('part Content-transfer-encoding');
  const contentLocation = h.get('content-location');
  if (!contentLocation) throw malformed('part Content-location missing');
  const hashAlgorithmId = h.get('hash-algorithm-id');
  if (!hashAlgorithmId) throw malformed('part Hash-algorithm-id missing');
  const hash = decodeBase64Strict(new TextDecoder().decode(body).trim());
  if (!hash || hash.length === 0) throw malformed('part hash is not base64');

  const part: DirectoryPart = { contentLocation, hashAlgorithmId, hash };
  const cid = h.get('content-identifier');
  if (cid !== undefined) {
    const [id, ...params] = cid.split(';');
    part.contentIdentifier = (id ?? '').trim();
    const instance = param(params, 'instance');
    if (instance !== undefined) part.instance = instance;
    if (part.contentIdentifier === SHARED_PARAMETERS || part.contentIdentifier === PRIVATE_PARAMETERS) {
      if (instance === undefined) throw malformed(`${part.contentIdentifier}: instance missing`);
      if (instance !== instanceIdentifier) {
        throw new GlobalConfError('INSTANCE_MISMATCH', `${part.contentIdentifier} instance '${instance}' ≠ anchor '${instanceIdentifier}'`);
      }
    }
  }
  return part;
}

/**
 * confVersion convention: `V<n>/<timestamp>` taken from the
 * SHARED-PARAMETERS Content-location, e.g. `V6/20261006121242895980000`.
 * It names the exact published shared-params and is reproducible from the
 * pinned snapshot's `.metadata` file.
 */
export function confVersionOf(contentLocation: string): string {
  return contentLocation.replace(/^\//, '').replace(/\/[^/]*$/, '');
}
