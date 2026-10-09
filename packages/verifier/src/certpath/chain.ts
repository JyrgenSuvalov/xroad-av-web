/**
 * SignatureVerifier.verifyCertificateChain (SV:392-398) → CertChainFactory.create
 * (CCF:87-97) → CertChainVerifier.verify (CCV:160-217)
 * The last step (S6) of the verification pipeline.
 *
 *   verifyCertificateChain(input) → CertChainResult
 *
 * Java evaluation order and fault codes:
 *   1. signature.getExtraCertificates()             malformed_signature (unprefixed; certpath/extra.ts)
 *   2. getCaCert(signer.instance, signingCert)       cannot_create_cert_path.<code> (internal_error if unapproved)
 *   3. signature.getOcspResponses()                  malformed_signature (unprefixed; ocsp/extract.ts)
 *   4. PKIX build at atDate                          cannot_create_cert_path.internal_error (certpath/pkix.ts)
 *   5. for the EE: getCaCert, find the response by CertID
 *        none → invalid_cert_path.cert_validation "Unable to find OCSP response for certificate <RFC 2253 subject>"
 *   6. OcspVerifier.verifyValidityAndStatus          invalid_cert_path.<code> (ocsp/verify.ts)
 *   Anything else thrown in 4–6 → invalid_cert_path.internal_error (translateWithPrefix).
 */
import type * as pkijs from 'pkijs';
import { CodedError, ErrorCodes, translateException } from '../util/errors';
import type { ApprovedCa, TrustContext } from '../types';
import { trustQueries } from '../trust/queries';
import type { XDocument, XElement } from '../xml/safe';
import { getOcspResponses } from '../ocsp/extract';
import { jdkRfc2253 } from '../ocsp/names';
import { findOcspResponseForCert, trustedCert, verifyValidityAndStatus, type OcspResult } from '../ocsp/verify';
import { getExtraCertificates } from './extra';
import { verifyPkix } from './pkix';

export interface CertChainInput {
  /** The signatures.xml document and its first ds:Object (xml/signature-doc SignatureDocument). */
  signature: { doc: XDocument; object: XElement };
  /** The signing certificate (xades getSigningCertificate). */
  signingCert: { der: Uint8Array; cert: pkijs.Certificate };
  /** signer.getXRoadInstance(): the instance of the ClientId derived from the message. */
  signerInstance: string;
  /** Timestamp genTime. */
  atDate: Date;
  trust: TrustContext;
  /** Wall clock, only for the non-main instance visibility filter. */
  now: Date;
  /** RFC 2253 formatter for fault strings (default: jdkRfc2253; verify.ts passes the src/result one). */
  formatName?: (nameDer: Uint8Array) => string;
}

export interface CertChainResult {
  /** The approved CA that issued the signing cert (trust anchor). */
  issuer: ApprovedCa;
  /** Extra certificates from CompleteCertificateRefs (validated only). */
  extraCertificates: Uint8Array[];
  ocsp: OcspResult;
}

function prefixed(prefix: string, e: unknown): CodedError {
  return translateException(e).withPrefix(prefix);
}

export async function verifyCertificateChain(input: CertChainInput): Promise<CertChainResult> {
  const { trust, now, atDate } = input;
  const q = trustQueries(trust);
  const ee = trustedCert(input.signingCert.der, input.signingCert.cert);
  const formatName = input.formatName ?? jdkRfc2253;

  const extraCertificates = await getExtraCertificates(input.signature.doc, input.signature.object);

  let anchor: ApprovedCa;
  try {
    anchor = q.getCaCert(input.signerInstance, ee, now);
  } catch (e) {
    throw prefixed(ErrorCodes.X_CANNOT_CREATE_CERT_PATH, e);
  }

  const responses = getOcspResponses(input.signature.object);

  // verifyPkix throws an already-prefixed cannot_create_cert_path error
  await verifyPkix(ee.cert, anchor.cert.cert, atDate);

  try {
    const issuer = q.getCaCert(input.signerInstance, ee, now);
    const response = await findOcspResponseForCert(ee.cert, issuer.cert, responses);
    if (!response) {
      throw new CodedError(
        ErrorCodes.X_CERT_VALIDATION,
        `Unable to find OCSP response for certificate ${formatName(ee.subjectDer)}`,
      );
    }
    const ocsp = await verifyValidityAndStatus(response, ee.cert, issuer.cert, atDate, { trust, now });
    return { issuer: anchor, extraCertificates, ocsp };
  } catch (e) {
    throw prefixed(ErrorCodes.X_INVALID_CERT_PATH_X, e);
  }
}

