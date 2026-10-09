/**
 * Step S4: SignatureVerifier.verifySignatureValue (SV:356-370), i.e. Santuario
 * XMLSignature.checkSignatureValue(cert) with X-Road's resolvers
 * (IdResolver, then the ASiC resolver ACV:190-209). SANTUARIO-RULES §3, §6, §7.
 *
 *   await verifySignatureValue(sd, container, signingCert)   - resolves, or throws CodedError
 *   getSignatureValueBytes(sd)                               - XMLSignature.getSignatureValue(): the
 *       non-batch timestamped data (ACV getTimestampedData, step V6)
 *
 * Order (checkSignatureValue):
 *   1. import the certificate key for the SignatureMethod   key does not fit → internal_error
 *   2. canonicalise ds:SignedInfo                            unsupported c14n → internal_error
 *   3. decode ds:SignatureValue (Java MIME base64)           bad padding → internal_error
 *   4. verify                                                false → invalid_signature_value
 *      (references are NOT resolved when the signature is invalid)
 *   5. every Reference, in order, with no short-circuit on a mismatch:
 *      Reference ctor (model.ts referenceAt)                 → internal_error
 *      decode DigestValue                                    bad padding → internal_error
 *      resolve the URI:
 *        no URI attribute                                    → internal_error (IdResolver NPE)
 *        '#id'  first element with an unqualified Id = id, as inclusive C14N 1.0 without
 *               comments; no such element                    → internal_error (NPE on null input)
 *        '/attachment…' with a container digest: the precomputed SHA-512, compared as bytes;
 *               DigestMethod is not consulted
 *        a container entry (hashchain containerHasEntry): its UTF-8 bytes, raw
 *        ''     the whole document, inclusive C14N 1.0 without comments (ResolverFragment)
 *        anything else                                       → internal_error (MissingResourceFailure)
 *      unknown / MD5 / unsupported DigestMethod               → internal_error
 *      any ds:Transforms                                     → internal_error (port deviation)
 *      a digest mismatch anywhere                            → invalid_signature_value
 * Any exception aborts the whole check.
 *
 * Supported c14n for SignedInfo: inclusive C14N 1.0 with or without comments.
 * Port deviation: the other Santuario c14n algorithms (exclusive, 1.1) give
 * internal_error, as an unknown URI does in Java. Reference Transforms are not
 * implemented either; X-Road containers use neither.
 */
import { C14N_10, C14N_10_WITH_COMMENTS, canonicalize } from '../c14n/c14n';
import type { AsicContainer } from '../container/read';
import { attachmentDigest, containerEntryBytes, containerHasEntry, isAttachmentUri } from '../hashchain/asic';
import { digest, DIGEST_URIS } from '../hashchain/digest';
import { bytesEqual } from '../util/bytes';
import { CodedError, ErrorCodes } from '../util/errors';
import type { SignatureDocument } from '../xml/signature-doc';
import type { XDocument, XElement, XNode } from '../xml/safe';
import { decodeDsBase64, dsText } from './base64';
import type { SigningCertificate } from './cert';
import { importVerificationKey, verifyWithKey } from './crypto';
import { readSignatureModel, referenceAt, referenceCount, type ReferenceModel, type SignatureModel } from './model';

const internal = (msg: string) => new CodedError(ErrorCodes.X_INTERNAL_ERROR, msg);
const invalid = () => new CodedError(ErrorCodes.X_INVALID_SIGNATURE_VALUE, 'Signature is not valid');

export function getSignatureValueBytes(sd: SignatureDocument): Uint8Array {
  return decodeDsBase64(dsText(readSignatureModel(sd.signature).signatureValueElement));
}

export async function verifySignatureValue(
  sd: SignatureDocument,
  container: AsicContainer,
  signingCert: SigningCertificate,
): Promise<void> {
  const model = readSignatureModel(sd.signature);
  const key = await importVerificationKey(model.signatureMethod, signingCert.cert);
  const signedInfo = canonicalizeSignedInfo(model);
  const signatureValue = getSignatureValueBytes(sd);
  if (!(await verifyWithKey(key, signedInfo, signatureValue))) throw invalid();
  if (!(await verifyReferences(sd.doc, model, container))) throw invalid();
}

function canonicalizeSignedInfo(model: SignatureModel): Uint8Array {
  const uri = model.canonicalizationMethod;
  if (uri !== C14N_10 && uri !== C14N_10_WITH_COMMENTS) {
    throw internal(`InvalidCanonicalizerException: Unsupported canonicalization method "${uri}"`);
  }
  return canonicalize(model.signedInfo, { withComments: uri === C14N_10_WITH_COMMENTS });
}

async function verifyReferences(doc: XDocument, model: SignatureModel, container: AsicContainer): Promise<boolean> {
  let all = true;
  for (let i = 0; i < referenceCount(model); i++) {
    if (!(await verifyReference(doc, referenceAt(model, i), container))) all = false;
  }
  return all;
}

type Input = { kind: 'precomputed'; digest: Uint8Array } | { kind: 'node'; node: XNode } | { kind: 'bytes'; bytes: Uint8Array };

async function verifyReference(doc: XDocument, ref: ReferenceModel, container: AsicContainer): Promise<boolean> {
  const expected = decodeDsBase64(dsText(ref.digestValueElement));
  const input = resolve(doc, ref, container);
  if (input.kind === 'precomputed') return bytesEqual(expected, input.digest);
  if (ref.digestMethod === DIGEST_URIS.MD5) {
    throw internal('XMLSignatureException: MD5 digests are not allowed with secure validation');
  }
  if (ref.transforms.length > 0) {
    throw internal(`Reference transforms are not supported by this verifier: ${ref.transforms.join(', ')}`);
  }
  const data = input.kind === 'node' ? canonicalize(input.node) : input.bytes;
  return bytesEqual(expected, await digest(ref.digestMethod, data));
}

function resolve(doc: XDocument, ref: ReferenceModel, container: AsicContainer): Input {
  const uri = ref.uri;
  if (uri === null) {
    throw internal('Cannot invoke "org.w3c.dom.Attr.getValue()" because "context.attr" is null');
  }
  if (uri.startsWith('#')) {
    const el = elementById(doc, uri.slice(1));
    if (!el) {
      throw internal(
        'Cannot invoke "org.apache.xml.security.signature.XMLSignatureInput.getPreCalculatedDigest()" because "input" is null',
      );
    }
    return { kind: 'node', node: el };
  }
  if (isAttachmentUri(uri)) {
    const d = attachmentDigest(container, uri);
    if (d) return { kind: 'precomputed', digest: d };
  } else if (containerHasEntry(container, uri)) {
    return { kind: 'bytes', bytes: containerEntryBytes(container, uri)! };
  }
  if (uri === '') return { kind: 'node', node: doc };
  throw internal(`MissingResourceFailureException: The Reference for URI ${uri} has no XMLSignatureInput`);
}

/** XmlUtils.getElementById: XPath //*[@Id = id], the first in document order. */
function elementById(doc: XDocument, id: string): XElement | null {
  const stack: XNode[] = [];
  for (let n = doc.lastChild; n; n = n.previousSibling) stack.push(n);
  while (stack.length > 0) {
    const n = stack.pop()!;
    if (n.nodeType !== 1) continue;
    const el = n as XElement;
    const a = el.getAttributeNodeNS(null, 'Id');
    if (a && a.value === id) return el;
    for (let c = el.lastChild; c; c = c.previousSibling) stack.push(c);
  }
  return null;
}
