import type { Certificate } from 'pkijs';

// Result model. JSON-serialisable; rendered by the UI.

export type VerificationResult =
  | {
      ok: true;
      signer: { id: string; cert: CertSummary };
      ocsp: { signedBy: CertSummary; producedAt: string }; // ISO-8601 UTC
      timestamp: { signedBy: CertSummary; genTime: string }; // ISO-8601 UTC
      attachmentDigests: { uri: string; digestHex: string; verified: boolean }[];
      confVersion: string;
    }
  | { ok: false; faultCode: string; faultString: string; confVersion: string };

export type CertSummary = {
  subject: string;
  issuer: string;
  serialNumber: string; // decimal, as in Java
  notBefore: string; // ISO-8601 UTC
  notAfter: string; // ISO-8601 UTC
};

/** DER-backed certificate. Built by globalconf/trust.ts. */
export interface TrustedCert {
  readonly der: Uint8Array;
  /** DER of the subject Name (issuer lookups, OCSP nameHash). */
  readonly subjectDer: Uint8Array;
  /** Parsed form of `der`. */
  readonly cert: Certificate;
}

/** One CA certificate (topCA or intermediateCA) from shared-params `approvedCA`. */
export interface ApprovedCa {
  cert: TrustedCert;
  /** approvedCA/certificateProfileInfo of the containing approvedCA. */
  certificateProfileInfo: string;
  /** Name of the containing approvedCA (display only). */
  caName: string;
  /** approvedCA/authenticationOnly (Java still uses these certs for getCaCert). */
  authenticationOnly: boolean;
  /** ocsp/cert entries configured under THIS CA cert (isOcspResponderCert). Document order. */
  ocspResponderCerts: TrustedCert[];
  /** ocsp/url entries under this CA cert (display only). */
  ocspUrls: string[];
}

export interface InstanceTrust {
  instanceId: string;
  /** Configuration version for VerificationResult.confVersion (see globalconf/directory.ts confVersionOf). */
  confVersion: string;
  /** Directory Expire-date (ISO-8601 UTC); filters NON-main instances only. null = never expires. */
  expiresAt: string | null;
  /** All topCA + intermediateCA certs, flattened in document order. */
  approvedCas: ApprovedCa[];
  /** approvedTSA/cert, document order. */
  tsaCerts: TrustedCert[];
  /** globalSettings/ocspFreshnessSeconds. */
  ocspFreshnessSeconds: number;
}

/**
 * Verified global configuration the container is checked against.
 * Pure data plus `visibleInstances`; the
 * GlobalConfImpl-like query helpers (TrustQueries) live in the verifier core (src/trust/queries.ts).
 */
export interface TrustContext {
  /** instance-identifier of the configuration (anchor instance). */
  readonly mainInstance: string;
  /** confVersion of the main instance; echoed into every result. */
  readonly confVersion: string;
  /** nextupdate-params.xml verifyNextUpdate; true when absent. */
  readonly verifyOcspNextUpdate: boolean;
  /** Main instance (never filtered, even when expired) plus non-main instances with expiresAt > now. */
  visibleInstances(now: Date): InstanceTrust[];
}
