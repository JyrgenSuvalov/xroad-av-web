/**
 * PKIX build + validate of the signer certificate at atDate
 * (CertChainVerifier, CCV:102-238). The trust anchor
 * is the signer cert's DIRECT issuer from globalconf (getCaCert), so the path
 * is always [signingCert] and only the end-entity checks apply:
 *
 *   - signature verifies under the anchor's public key;
 *   - notBefore ≤ atDate ≤ notAfter (X509Certificate.checkValidity(atDate));
 *   - no unrecognised critical extension (JDK PKIXCertPathChecker set);
 *   - JDK disabled algorithms: MD2/MD5 signatures (WebCrypto cannot verify them
 *     anyway), RSA keys < 1024 bits.
 *   The anchor's own validity is NOT checked.
 *
 *   verifyPkix(ee, anchor, atDate) → void
 *     any failure → cannot_create_cert_path.internal_error
 *                   "unable to find valid certification path to requested target"
 *     (SunCertPathBuilderException: the JDK builder reports every EE failure,
 *     expiry and bad signature alike, as a build failure).
 *
 * UNCONFIRMED (not exercised by any container checked against the jar):
 *   the exact JDK message variants, the critical-extension set, and whether an
 *   AuthorityKeyIdentifier/SubjectKeyIdentifier mismatch with the anchor fails
 *   the build.
 */
import type * as pkijs from 'pkijs';
import { CodedError, ErrorCodes } from '../util/errors';
import { certSignedBy } from '../ocsp/verify';

export const PKIX_BUILD_FAILURE = 'unable to find valid certification path to requested target';

/** Extensions the JDK PKIX checkers process (Basic/Key/Constraints/Policy/NameConstraints/AltName checkers). */
const KNOWN_CRITICAL = new Set([
  '2.5.29.15', // keyUsage
  '2.5.29.19', // basicConstraints
  '2.5.29.37', // extKeyUsage
  '2.5.29.17', // subjectAltName
  '2.5.29.30', // nameConstraints
  '2.5.29.32', // certificatePolicies
  '2.5.29.33', // policyMappings
  '2.5.29.36', // policyConstraints
  '2.5.29.54', // inhibitAnyPolicy
]);

const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

function buildFailure(detail: string): CodedError {
  return new CodedError(ErrorCodes.X_INTERNAL_ERROR, PKIX_BUILD_FAILURE, {
    cause: new Error(detail),
  }).withPrefix(ErrorCodes.X_CANNOT_CREATE_CERT_PATH);
}

function rsaModulusBits(cert: pkijs.Certificate): number | null {
  if (cert.subjectPublicKeyInfo.algorithm.algorithmId !== RSA_ENCRYPTION) return null;
  const parsed = cert.subjectPublicKeyInfo.parsedKey as pkijs.RSAPublicKey | undefined;
  const mod = parsed?.modulus?.valueBlock.valueHexView;
  if (!mod) return null;
  let i = 0;
  while (i < mod.length && mod[i] === 0) i++;
  if (i === mod.length) return 0;
  return (mod.length - i - 1) * 8 + (32 - Math.clz32(mod[i]!));
}

export async function verifyPkix(ee: pkijs.Certificate, anchor: pkijs.Certificate, atDate: Date): Promise<void> {
  const t = atDate.getTime();
  if (t < ee.notBefore.value.getTime()) throw buildFailure(`certificate not yet valid at ${atDate.toISOString()}`);
  if (t > ee.notAfter.value.getTime()) throw buildFailure(`certificate expired at ${atDate.toISOString()}`);
  const bits = rsaModulusBits(ee);
  if (bits !== null && bits < 1024) throw buildFailure(`RSA key size ${bits} is disabled`);
  if (!(await certSignedBy(ee, anchor))) throw buildFailure('signature does not verify under the trust anchor');
  const unknown = (ee.extensions ?? []).find((e) => e.critical && !KNOWN_CRITICAL.has(e.extnID));
  if (unknown) throw buildFailure(`unrecognised critical extension ${unknown.extnID}`);
}
