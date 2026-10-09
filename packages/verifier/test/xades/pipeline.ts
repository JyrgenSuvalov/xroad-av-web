// The XAdES part of AsicContainerVerifier.verify, composed for tests only:
// V2 → V5 → S1 → S2 → S4. The timestamp (V6), signer binding
// (S3) and the cert path (S6) are left out; src/verify.ts composes the real pipeline.
import { ENTRY_SIGNATURE, readContainer } from '../../src/container/read';
import { verifySignatureHashChain } from '../../src/hashchain';
import { translateException } from '../../src/util/errors';
import { loadSignatureDocument, type SignatureHooks } from '../../src/xml/signature-doc';
import {
  checkMessagePartsReferenced,
  checkRequiredReferences,
  checkSignatureElement,
  getSigningCertificate,
  isBatchSignature,
  readSignatureModel,
  verifySignatureValue,
} from '../../src/xades';

export type XadesOutcome = { ok: true } | { ok: false; faultCode: string; faultString: string };

export const hooks: SignatureHooks = { checkSignatureElement };

export async function runXades(bytes: Uint8Array): Promise<XadesOutcome> {
  try {
    const container = await readContainer(bytes, { signatureHooks: hooks });
    const sd = loadSignatureDocument(container.get(ENTRY_SIGNATURE)!, hooks);
    const model = readSignatureModel(sd.signature);
    checkRequiredReferences(model);
    if (isBatchSignature(container, model)) await verifySignatureHashChain(container);
    else checkMessagePartsReferenced(model);
    const cert = getSigningCertificate(model);
    await verifySignatureValue(sd, container, cert);
    return { ok: true };
  } catch (e) {
    const c = translateException(e);
    return { ok: false, faultCode: c.faultCode, faultString: c.faultString };
  }
}
