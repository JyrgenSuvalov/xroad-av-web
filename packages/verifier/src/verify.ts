/**
 * AsicContainerVerifier.verify (ACV:132-179), composed from the modules in
 * the exact Java order (docs/architecture.md). The order decides which fault
 * code wins, so do not reorder steps:
 *
 *   read   AsicContainer.read (+ xades checkSignatureElement hooks)
 *   V2     new Signature(signatures.xml)
 *   V3     getSigner(message); signerError.thrown → internal_error
 *   V5     checkRequiredReferences
 *   V6     timestamp: parse token → stamped data (batch: ts hash chain,
 *          else SignatureValue bytes) → TSA verify; atDate = genTime
 *   S1     batch ? sig hash chain (attachment lines) : message parts
 *   S2     getSigningCertificate
 *   S3     signer binding (null signer → internal_error here)
 *   S4     signature value + references
 *   S6     cert chain + OCSP at atDate
 *   V9     result details
 *
 * Every non-CodedError goes through translateException.
 */
import { ENTRY_SIGNATURE, readContainer } from './container/read';
import { verifySignatureHashChain, verifyTimestampHashChain, type AttachmentDigest } from './hashchain';
import { parseMessage } from './header/index';
import { verifyCertificateChain } from './certpath';
import { trustedCert } from './ocsp/verify';
import { verifySignerName } from './binding';
import { certSummary } from './result';
import { parseTimestampToken, verifyTimestampToken } from './timestamp';
import type { TrustContext, VerificationResult } from './types';
import { CodedError, ErrorCodes, translateException } from './util/errors';
import { loadSignatureDocument, type SignatureHooks } from './xml/signature-doc';
import {
  checkMessagePartsReferenced,
  checkRequiredReferences,
  checkSignatureElement,
  getSignatureValueBytes,
  getSigningCertificate,
  isBatchSignature,
  readSignatureModel,
  verifySignatureValue,
} from './xades';

export interface VerifyOptions {
  /** Wall clock for the non-main instance visibility filter (default: new Date()). */
  now?: Date;
}

const hooks: SignatureHooks = { checkSignatureElement };

/** Java's ISO-8601 UTC with milliseconds. */
function iso(d: Date): string {
  return d.toISOString();
}

/**
 * Verify an ASiC-E container against a verified global configuration.
 * Never throws: every failure becomes `{ ok: false, faultCode, faultString }`.
 */
export async function verifyContainer(
  bytes: Uint8Array,
  trust: TrustContext,
  opts: VerifyOptions = {},
): Promise<VerificationResult> {
  const now = opts.now ?? new Date();
  const confVersion = trust.confVersion;
  try {
    // read
    const container = await readContainer(bytes, { signatureHooks: hooks });

    // V2
    const sd = loadSignatureDocument(container.get(ENTRY_SIGNATURE) ?? '', hooks);
    const model = readSignatureModel(sd.signature);

    // V3
    const message = parseMessage(container);
    if (message.signerError?.thrown) {
      throw new CodedError(message.signerError.faultCode, message.signerError.faultString);
    }
    const signer = message.expectedSigner;
    const signerId = message.expectedSignerId;

    // V5
    checkRequiredReferences(model);

    // V6: the token is parsed before the stamped data is computed.
    const token = parseTimestampToken(container.timestampDer);
    const stampedData = (await verifyTimestampHashChain(container)) ?? getSignatureValueBytes(sd);
    const ts = await verifyTimestampToken(token, stampedData, trust, now);
    const atDate = ts.genTime;

    // S1 (V7 clears anything the ts hash chain logged: only sig hash chain lines survive)
    let attachmentDigests: AttachmentDigest[] = [];
    if (isBatchSignature(container, model)) attachmentDigests = await verifySignatureHashChain(container);
    else checkMessagePartsReferenced(model);

    // S2
    const signing = getSigningCertificate(model);

    // S3 (Java: NPE on a null signer → internal_error)
    if (signer === null || signerId === null) {
      throw new CodedError(
        ErrorCodes.X_INTERNAL_ERROR,
        message.signerError?.faultString ?? 'Cannot derive the signer from the message (signer is null)',
      );
    }
    verifySignerName(trust, signer, trustedCert(signing.der, signing.cert), now);

    // S4
    await verifySignatureValue(sd, container, signing);

    // S6
    const chain = await verifyCertificateChain({
      signature: { doc: sd.doc, object: sd.object },
      signingCert: signing,
      signerInstance: signer.xRoadInstance,
      atDate,
      trust,
      now,
    });

    // V9
    return {
      ok: true,
      signer: { id: signerId, cert: certSummary(signing.cert) },
      ocsp: { signedBy: certSummary(chain.ocsp.responderCert.cert), producedAt: iso(chain.ocsp.producedAt) },
      timestamp: { signedBy: certSummary(ts.tsaCert.cert), genTime: iso(atDate) },
      attachmentDigests,
      confVersion,
    };
  } catch (e) {
    const c = translateException(e);
    return { ok: false, faultCode: c.faultCode, faultString: c.faultString, confVersion };
  }
}
