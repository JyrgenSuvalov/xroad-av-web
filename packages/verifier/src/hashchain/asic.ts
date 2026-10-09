/**
 * The two hash-chain usages in ASiC verification.
 *
 *   await verifySignatureHashChain(container) → AttachmentDigest[]
 *     SignatureVerifier.verifyHashChain (SV:328-341), step S1 for a batch
 *     signature. Result = sig-hashchainresult.xml, inputs = {/message.xml}.
 *     Returns the attachment digest lines (DataRefs that are not
 *     container entries; their digests are trusted and only labelled).
 *     Faults: every failure is `malformed_signature.<inner>`, where inner is
 *       invalid_hash_chain | malformed_hash_chain | invalid_hash_chain_ref |
 *       invalid_reference | hashchain_unused_inputs | internal_error
 *     (Java catches Throwable and applies translateException + withPrefix).
 *     Precondition (caller, step S1): the container has sig-hashchainresult.xml and
 *     the signature references '/sig-hashchainresult.xml' (see isBatchSignature).
 *
 *   await verifyTimestampHashChain(container) → Uint8Array | null
 *     AsicContainerVerifier.verifyTimestampHashChain + getTimestampedData's batch
 *     branch (ACV:233-257), step V6. If the container has a ts-hashchainresult.xml
 *     entry, verifies the chain (inputs = {/META-INF/signatures.xml}) and returns
 *     the UTF-8 bytes of ts-hashchainresult.xml: the data the timestamp's
 *     messageImprint must cover. Returns null when there is no ts hash chain
 *     (the timestamp then covers the decoded ds:SignatureValue, see
 *     xades getSignatureValueBytes).
 *     Faults: any failure → plain `malformed_signature`
 *       "Failed to verify time-stamp hash chain: <inner>".
 *
 *   createAsicResolver(container, onUnresolvable?) - the ACV HashChainReferenceResolverImpl
 *   containerEntryBytes(container, uri) - AsicContainer.getEntry (UTF-8 bytes) or null
 *   containerHasEntry(container, uri)   - AsicContainer.hasEntry (text entries only)
 */
import type { AsicContainer } from '../container/read';
import { ENTRY_SIG_HASH_CHAIN_RESULT, ENTRY_TIMESTAMP, ENTRY_TS_HASH_CHAIN_RESULT, stripSlash } from '../container/read';
import { bytesEqual, encodeUtf8, toHex } from '../util/bytes';
import { CodedError, ErrorCodes, translateException } from '../util/errors';
import { verifyHashChain, type HashChainReferenceResolver } from './verifier';

export const URI_MESSAGE = '/message.xml';
export const URI_SIGNATURE = '/META-INF/signatures.xml';
export const URI_SIG_HASH_CHAIN_RESULT = '/sig-hashchainresult.xml';
export const URI_ATTACHMENT_PREFIX = '/attachment';

export interface AttachmentDigest {
  /** DataRef URI exactly as written (with its leading slash). */
  uri: string;
  /** Lowercase hex of the DataRef DigestValue. */
  digestHex: string;
  /** True iff the URI is an attachment and its digest equals SHA-512 of the attachment entry. */
  verified: boolean;
}

/**
 * The value Java's AsicContainer stores for an entry name. Java keeps
 * META-INF/timestamp.tst in the same map as base64 text, so it is an entry too.
 */
function entryValue(container: AsicContainer, uri: string): string | undefined {
  const name = stripSlash(uri);
  if (name === ENTRY_TIMESTAMP && container.timestampTst) return container.timestampValue;
  return container.entries.get(name);
}

/** Java AsicContainer.hasEntry: text entries only (attachments are not entries). */
export function containerHasEntry(container: AsicContainer, uri: string): boolean {
  return entryValue(container, uri) !== undefined;
}

/** Java AsicContainer.getEntry: UTF-8 bytes of the stored string, or null. */
export function containerEntryBytes(container: AsicContainer, uri: string): Uint8Array | null {
  const v = entryValue(container, uri);
  return v === undefined ? null : encodeUtf8(v);
}

/** MessageFileNames.isAttachment. */
export function isAttachmentUri(uri: string): boolean {
  return uri.startsWith(URI_ATTACHMENT_PREFIX);
}

/** AsicContainer.getAttachmentDigest (stripSlash lookup). */
export function attachmentDigest(container: AsicContainer, uri: string): Uint8Array | undefined {
  return container.attachmentDigests.get(stripSlash(uri));
}

export function createAsicResolver(
  container: AsicContainer,
  onUnresolvable?: (uri: string, digestValue: Uint8Array) => void,
): HashChainReferenceResolver {
  return {
    shouldResolve(uri, digestValue) {
      if (containerHasEntry(container, uri)) return true;
      onUnresolvable?.(uri, digestValue);
      return false;
    },
    resolve: (uri) => containerEntryBytes(container, uri),
  };
}

export async function verifySignatureHashChain(container: AsicContainer): Promise<AttachmentDigest[]> {
  const lines: AttachmentDigest[] = [];
  const resolver = createAsicResolver(container, (uri, digestValue) => {
    const expected = attachmentDigest(container, uri);
    lines.push({
      uri,
      digestHex: toHex(digestValue),
      verified: isAttachmentUri(uri) && expected !== undefined && bytesEqual(digestValue, expected),
    });
  });
  try {
    await verifyHashChain(container.get(ENTRY_SIG_HASH_CHAIN_RESULT) ?? '', resolver, [URI_MESSAGE]);
  } catch (e) {
    throw translateException(e).withPrefix(ErrorCodes.X_MALFORMED_SIGNATURE);
  }
  return lines;
}

export async function verifyTimestampHashChain(container: AsicContainer): Promise<Uint8Array | null> {
  const result = container.get(ENTRY_TS_HASH_CHAIN_RESULT);
  if (result === undefined) return null;
  const bytes = encodeUtf8(result);
  try {
    await verifyHashChain(result, createAsicResolver(container), [URI_SIGNATURE]);
  } catch (e) {
    const inner = translateException(e);
    throw new CodedError(
      ErrorCodes.X_MALFORMED_SIGNATURE,
      `Failed to verify time-stamp hash chain: ${inner.faultCode}: ${inner.faultString}`,
      { cause: e },
    );
  }
  return bytes;
}
