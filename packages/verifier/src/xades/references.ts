/**
 * Reference-presence checks on the signature (raw URI string compares, SIG:169-179).
 *
 *   signatureReferences(sig, uri)        - Signature.references(uri): walks SignedInfo.item(i), which
 *       constructs each Reference (model.ts referenceAt: internal_error on a broken Reference), and
 *       stops at the first match
 *   checkRequiredReferences(sig)         - step V5 (ACV:181-188)
 *       malformed_signature "Signature does not reference '/message.xml' or '/sig-hashchainresult.xml'"
 *   isBatchSignature(container, sig)     - step S1 branch (SV:290-297): the container has
 *       sig-hashchainresult.xml AND the signature references '/sig-hashchainresult.xml'.
 *       True → hashchain verifySignatureHashChain; false → checkMessagePartsReferenced.
 *   checkMessagePartsReferenced(sig)     - step S1 non-batch (SV:314-326); the only part is /message.xml
 *       malformed_signature "Signature does not reference '/message.xml'"
 */
import { ENTRY_SIG_HASH_CHAIN_RESULT, type AsicContainer } from '../container/read';
import { URI_MESSAGE, URI_SIG_HASH_CHAIN_RESULT } from '../hashchain/asic';
import { CodedError, ErrorCodes } from '../util/errors';
import { referenceAt, referenceCount, type SignatureModel } from './model';

export function signatureReferences(sig: SignatureModel, uri: string): boolean {
  for (let i = 0; i < referenceCount(sig); i++) if (referenceAt(sig, i).uri === uri) return true;
  return false;
}

export function checkRequiredReferences(sig: SignatureModel): void {
  if (!signatureReferences(sig, URI_MESSAGE) && !signatureReferences(sig, URI_SIG_HASH_CHAIN_RESULT)) {
    throw new CodedError(
      ErrorCodes.X_MALFORMED_SIGNATURE,
      `Signature does not reference '${URI_MESSAGE}' or '${URI_SIG_HASH_CHAIN_RESULT}'`,
    );
  }
}

export function isBatchSignature(container: AsicContainer, sig: SignatureModel): boolean {
  return container.get(ENTRY_SIG_HASH_CHAIN_RESULT) !== undefined && signatureReferences(sig, URI_SIG_HASH_CHAIN_RESULT);
}

export function checkMessagePartsReferenced(sig: SignatureModel): void {
  if (!signatureReferences(sig, URI_MESSAGE)) {
    throw new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, `Signature does not reference '${URI_MESSAGE}'`);
  }
  // The only added part is /message.xml (ACV:162-169), so "Message part ... is
  // not covered by the signature" cannot occur once the check above passes.
}
