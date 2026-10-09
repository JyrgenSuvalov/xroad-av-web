/**
 * Certificate-profile registry: the port of GetCertificateProfile + the
 * SignCertificateProfileInfo.getSubjectIdentifier implementations.
 * A profile is looked up by the approvedCA's
 * `certificateProfileInfo` Java class name.
 *
 *   signCertProfile(className)              → SignCertProfile (throws internal_error if unknown)
 *   registerSignCertProfile(className, p)   - add/replace a profile (tests, other instances)
 *   BASIC_PROFILE                           - BasicCertificateProfileInfoProvider
 *   getRdnValue(nameDer, oid)               - CertUtils.getRDNValue over `new X500Name(principal.getName())`
 *
 * Only Basic is implemented. The other
 * 7.8.3 profiles (Ejbca, BasicACME, FiVRK, Fo, Is, SkKlass3, SkEsteId) fail with
 * the Java "could not be found in classpath" error until someone ports them.
 */
import * as asn1js from 'asn1js';
import { CodedError, ErrorCodes } from '../util/errors';
import type { ClientId } from '../header/ids';
import { createClientId, IdentifierError } from '../header/ids';
import type { TrustedCert } from '../types';
import { rdnValueToString } from '../trust/x500';

export interface SignCertProfile {
  /** SignCertificateProfileInfo.getSubjectIdentifier(cert), with the profile parameters' instance. */
  subjectIdentifier(signerInstance: string, cert: TrustedCert): ClientId;
}

export const BASIC_PROFILE_CLASS = 'ee.ria.xroad.common.certificateprofile.impl.BasicCertificateProfileInfoProvider';

export const OID_BUSINESS_CATEGORY = '2.5.4.15';
export const OID_SERIAL_NUMBER = '2.5.4.5';

/**
 * CertUtils.getRDNValue(new X500Name(cert.getSubjectX500Principal().getName()), oid).
 *
 * Probed against BC 1.84 + JDK 21 (see
 * src/binding/README.md): the JDK RFC 2253 string lists RDNs in REVERSE DER
 * order and BC keeps the string order, so "the first RDN containing oid" is the
 * LAST such RDN in DER order. For a multi-valued RDN BC returns that RDN's
 * first AVA, which need not be of type `oid` (DER SET order here; UNCONFIRMED).
 * The value is IETFUtils.valueToString (RFC 2253-escaped; non-strings '#hex').
 * Returns null when no RDN contains the attribute type.
 */
export function getRdnValue(nameDer: Uint8Array, oid: string): string | null {
  const parsed = asn1js.fromBER(nameDer);
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) {
    throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, 'Cannot decode certificate subject name');
  }
  const rdns = parsed.result.valueBlock.value;
  for (let i = rdns.length - 1; i >= 0; i--) {
    const set = rdns[i]!;
    if (!(set instanceof asn1js.Set)) continue;
    const avas = set.valueBlock.value.filter(
      (a): a is asn1js.Sequence => a instanceof asn1js.Sequence && a.valueBlock.value.length === 2,
    );
    const contains = avas.some((a) => {
      const t = a.valueBlock.value[0];
      return t instanceof asn1js.ObjectIdentifier && t.valueBlock.toString() === oid;
    });
    if (contains) return rdnValueToString(avas[0]!.valueBlock.value[1]!);
  }
  return null;
}

/** BasicCertificateProfileInfoProvider.BasicSignCertificateProfileInfo.getSubjectIdentifier (BCPIP:126-146). */
export const BASIC_PROFILE: SignCertProfile = {
  subjectIdentifier(signerInstance, cert) {
    const memberClass = getRdnValue(cert.subjectDer, OID_BUSINESS_CATEGORY);
    if (memberClass === null) {
      throw new CodedError(
        ErrorCodes.X_INCORRECT_CERTIFICATE,
        'Certificate subject name does not contain business category',
      );
    }
    const memberCode = getRdnValue(cert.subjectDer, OID_SERIAL_NUMBER);
    if (memberCode === null) {
      throw new CodedError(ErrorCodes.X_INCORRECT_CERTIFICATE, 'Certificate subject name does not contain serial number');
    }
    try {
      return createClientId(signerInstance, memberClass, memberCode, null);
    } catch (e) {
      // ClientId.Conf.create validation: IllegalArgumentException → internal_error
      if (e instanceof IdentifierError) throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, e.message, { cause: e });
      throw e;
    }
  },
};

const registry = new Map<string, SignCertProfile>([[BASIC_PROFILE_CLASS, BASIC_PROFILE]]);

export function registerSignCertProfile(className: string, profile: SignCertProfile): void {
  registry.set(className, profile);
}

export function signCertProfile(className: string): SignCertProfile {
  const p = registry.get(className);
  if (!p) throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, `${className} could not be found in classpath`);
  return p;
}
