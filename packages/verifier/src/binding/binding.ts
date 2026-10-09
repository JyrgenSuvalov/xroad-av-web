/**
 * Signer binding: GlobalConfImpl.getSubjectName (GCI:284-293, 595-606, 801-815)
 * and SignatureVerifier.verifySignerName (SV:343-354)
 *
 *   subjectName(trust, signer, cert, now) → ClientId decoded from the cert via the CA's profile
 *   verifySignerName(trust, signer, cert, now) → void
 *     isSigningCert re-check fails       → internal_error
 *     CA not approved                     → internal_error (getCaCert)
 *     blank certificateProfileInfo        → internal_error "Could not find certificate profile info for certificate <DN>"
 *     unknown profile class               → internal_error "<class> could not be found in classpath"
 *     no businessCategory / serialNumber  → incorrect_certificate
 *     !signer.memberEquals(cn)            → incorrect_certificate
 *         "Name in certificate (<cn>) does not match name in message (<signer>)"
 * memberEquals: instance, memberClass, memberCode exact (case-sensitive); subsystem ignored.
 */
import { CodedError, ErrorCodes } from '../util/errors';
import type { TrustContext, TrustedCert } from '../types';
import { trustQueries } from '../trust/queries';
import { clientIdToString, type ClientId } from '../header/ids';
import { keyUsageBit } from '../xades/cert';
import { isJavaBlank } from '../util/bytes';
import { jdkRfc2253 } from '../ocsp/names';
import { signCertProfile } from './profiles';

export function subjectName(trust: TrustContext, signer: ClientId, cert: TrustedCert, now: Date): ClientId {
  const nr = keyUsageBit(cert.cert, 1);
  if (nr === undefined) throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, 'Certificate does not contain keyUsage extension');
  if (!nr) throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, 'Certificate must be signing certificate');
  const ca = trustQueries(trust).getCaCert(signer.xRoadInstance, cert, now);
  if (isJavaBlank(ca.certificateProfileInfo)) {
    throw new CodedError(
      ErrorCodes.X_INTERNAL_ERROR,
      `Could not find certificate profile info for certificate ${jdkRfc2253(cert.subjectDer)}`,
    );
  }
  return signCertProfile(ca.certificateProfileInfo).subjectIdentifier(signer.xRoadInstance, cert);
}

export function memberEquals(a: ClientId, b: ClientId): boolean {
  return a.xRoadInstance === b.xRoadInstance && a.memberClass === b.memberClass && a.memberCode === b.memberCode;
}

export function verifySignerName(trust: TrustContext, signer: ClientId, cert: TrustedCert, now: Date): void {
  const cn = subjectName(trust, signer, cert, now);
  if (!memberEquals(signer, cn)) {
    throw new CodedError(
      ErrorCodes.X_INCORRECT_CERTIFICATE,
      `Name in certificate (${clientIdToString(cn)}) does not match name in message (${clientIdToString(signer)})`,
    );
  }
}
