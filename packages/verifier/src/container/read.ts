/**
 * ASiC container reading: port of AsicHelper.read + AsicContainer.verifyContents.
 * See container/README.md for research notes.
 *
 *   await readContainer(bytes, { limits?, signatureHooks? }) → AsicContainer
 *
 * Throws CodedError with the asicverifier content-check codes, in Java's order. Entry values are the
 * lenient UTF-8 decode of the bytes; `getBytes()` gives the UTF-8 re-encoding
 * that every later hash uses.
 */
import { decodeBase64Lenient, decodeUtf8, encodeBase64, encodeUtf8, isJavaBlank, sha512 } from '../util/bytes';
import { CodedError, ErrorCodes, translateException } from '../util/errors';
import { getSignatureTimestamp, loadSignatureDocument, type SignatureHooks } from '../xml/signature-doc';
import { DEFAULT_LIMITS, readZipEntries, type ContainerLimits } from './zip';

export const MIMETYPE = 'application/vnd.etsi.asic-e+zip';
export const ENTRY_MIMETYPE = 'mimetype';
export const ENTRY_MESSAGE = 'message.xml';
export const ENTRY_SIGNATURE = 'META-INF/signatures.xml';
export const ENTRY_SIG_HASH_CHAIN_RESULT = 'sig-hashchainresult.xml';
export const ENTRY_SIG_HASH_CHAIN = 'sig-hashchain.xml';
export const ENTRY_TS_HASH_CHAIN_RESULT = 'ts-hashchainresult.xml';
export const ENTRY_TS_HASH_CHAIN = 'ts-hashchain.xml';
export const ENTRY_MANIFEST = 'META-INF/manifest.xml';
export const ENTRY_ASIC_MANIFEST = 'META-INF/ASiCManifest.xml';
export const ENTRY_TIMESTAMP = 'META-INF/timestamp.tst';
export const ENTRY_ATTACHMENT = 'attachment';

const TEXT_ENTRIES = [
  ENTRY_MIMETYPE,
  ENTRY_MESSAGE,
  ENTRY_SIGNATURE,
  ENTRY_SIG_HASH_CHAIN_RESULT,
  ENTRY_SIG_HASH_CHAIN,
  ENTRY_TS_HASH_CHAIN_RESULT,
  ENTRY_TS_HASH_CHAIN,
  ENTRY_MANIFEST,
  ENTRY_ASIC_MANIFEST,
];

export interface AsicContainer {
  /** Text entries by canonical name (UTF-8 decoded, lenient). Excludes timestamp.tst. */
  readonly entries: ReadonlyMap<string, string>;
  /** Raw `META-INF/timestamp.tst` bytes, if present. */
  readonly timestampTst: Uint8Array | undefined;
  /** Java timestamp value: base64 of timestamp.tst, or the embedded token text. */
  readonly timestampValue: string;
  readonly timestampSource: 'tst' | 'embedded';
  /** Decoded timestamp token (DER) - lenient base64 decode of timestampValue. */
  readonly timestampDer: Uint8Array;
  /** Attachment name (e.g. `attachment1`) → SHA-512 of the raw bytes. */
  readonly attachmentDigests: ReadonlyMap<string, Uint8Array>;
  /** Attachment name → raw bytes (for download in the UI only). */
  readonly attachments: ReadonlyMap<string, Uint8Array>;
  /** Value by canonical entry name; one leading '/' is stripped (AsicHelper.stripSlash). */
  get(name: string): string | undefined;
  /** UTF-8 re-encoding of get(name) - the bytes Java hashes. */
  getBytes(name: string): Uint8Array | undefined;
  /** True if get(name) is defined, or name is an attachment with a digest. */
  hasEntry(name: string): boolean;
}

export interface ReadOptions {
  limits?: ContainerLimits;
  signatureHooks?: SignatureHooks;
}

export function stripSlash(name: string): string {
  return name.startsWith('/') ? name.slice(1) : name;
}

const notFound = (code: string, name: string) => new CodedError(code, `${name} not found or is empty`);

export async function readContainer(bytes: Uint8Array, options: ReadOptions = {}): Promise<AsicContainer> {
  const zipEntries = readZipEntries(bytes, options.limits ?? DEFAULT_LIMITS);
  const entries = new Map<string, string>();
  const attachments = new Map<string, Uint8Array>();
  let tst: Uint8Array | undefined;

  for (const { name, data } of zipEntries) {
    if (name === ENTRY_TIMESTAMP) {
      tst = data;
    } else if (TEXT_ENTRIES.includes(name)) {
      entries.set(name, decodeUtf8(data));
    } else if (name.startsWith(ENTRY_ATTACHMENT)) {
      attachments.set(name, data);
    }
    // Case variants of expected names and other META-INF/.*signatures.*\.xml
    // matches are read by Java but stored under a name that is never looked
    // up again: ignoring them is equivalent.
  }

  const attachmentDigests = new Map<string, Uint8Array>();
  for (const [name, data] of attachments) attachmentDigests.set(name, await sha512(data));

  const get = (name: string) => entries.get(name);

  // Content checks, in Java's order.
  const mime = get(ENTRY_MIMETYPE);
  if (isJavaBlank(mime)) throw notFound(ErrorCodes.X_ASIC_MIME_TYPE_NOT_FOUND, ENTRY_MIMETYPE);
  if (!equalsIgnoreCase(mime!, MIMETYPE)) {
    throw new CodedError(ErrorCodes.X_ASIC_INVALID_MIME_TYPE, `Invalid mime type: ${mime}`);
  }
  if (isJavaBlank(get(ENTRY_MESSAGE))) throw notFound(ErrorCodes.X_ASIC_MESSAGE_NOT_FOUND, ENTRY_MESSAGE);
  if (isJavaBlank(get(ENTRY_SIGNATURE))) throw notFound(ErrorCodes.X_ASIC_SIGNATURE_NOT_FOUND, ENTRY_SIGNATURE);
  checkHashChainPair(get, ENTRY_SIG_HASH_CHAIN_RESULT, ENTRY_SIG_HASH_CHAIN);

  let timestampValue: string;
  let timestampSource: 'tst' | 'embedded';
  if (tst) {
    timestampValue = encodeBase64(tst);
    timestampSource = 'tst';
  } else {
    try {
      timestampValue = getSignatureTimestamp(loadSignatureDocument(get(ENTRY_SIGNATURE)!, options.signatureHooks));
    } catch (e) {
      throw translateException(e);
    }
    timestampSource = 'embedded';
  }
  if (isJavaBlank(timestampValue)) throw notFound(ErrorCodes.X_ASIC_TIMESTAMP_NOT_FOUND, ENTRY_TIMESTAMP);
  checkHashChainPair(get, ENTRY_TS_HASH_CHAIN_RESULT, ENTRY_TS_HASH_CHAIN);

  for (const m of [ENTRY_MANIFEST, ENTRY_ASIC_MANIFEST]) {
    const v = get(m);
    if (v !== undefined && isJavaBlank(v)) throw notFound(ErrorCodes.X_ASIC_MANIFEST_NOT_FOUND, m);
  }

  return {
    entries,
    timestampTst: tst,
    timestampValue,
    timestampSource,
    timestampDer: tst ?? decodeBase64Lenient(timestampValue),
    attachmentDigests,
    attachments,
    get: (name) => entries.get(stripSlash(name)),
    getBytes: (name) => {
      const v = entries.get(stripSlash(name));
      return v === undefined ? undefined : encodeUtf8(v);
    },
    hasEntry: (name) => entries.has(stripSlash(name)) || attachmentDigests.has(stripSlash(name)),
  };
}

function checkHashChainPair(get: (n: string) => string | undefined, resultName: string, chainName: string): void {
  const result = get(resultName);
  const chain = get(chainName);
  if (isJavaBlank(result) && isJavaBlank(chain)) return;
  if (isJavaBlank(result)) throw notFound(ErrorCodes.X_ASIC_HASH_CHAIN_RESULT_NOT_FOUND, resultName);
  if (isJavaBlank(chain)) throw notFound(ErrorCodes.X_ASIC_HASH_CHAIN_NOT_FOUND, chainName);
}

/** Java String.equalsIgnoreCase (per-char upper/lower comparison). */
function equalsIgnoreCase(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a[i]!;
    const y = b[i]!;
    if (x === y) continue;
    const ux = x.toUpperCase();
    const uy = y.toUpperCase();
    if (ux === uy) continue;
    if (ux.toLowerCase() !== uy.toLowerCase()) return false;
  }
  return true;
}
