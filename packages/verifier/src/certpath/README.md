# certpath / ocsp / binding

Unit tests: test/{ocsp,binding,certpath}. Parity with the jar (every OCSP/binding tamper case: same faultCode + faultString; real containers: binding holds, chain + OCSP ok at genTime, same producedAt + responder) was checked on a container set that is not in this repository.

## API
- `certpath.verifyCertificateChain({ signature: {doc, object}, signingCert: {der, cert}, signerInstance, atDate, trust, now, formatName? })`
  → `{ issuer: ApprovedCa, extraCertificates, ocsp: { responderCert, responderSource, producedAt, thisUpdate, nextUpdate, response } }`.
  This is pipeline step S6. The Java order is: getExtraCertificates (malformed_signature) → getCaCert (cannot_create_cert_path.*) →
  getOcspResponses (malformed_signature) → PKIX (cannot_create_cert_path.internal_error) → OCSP lookup + verify (invalid_cert_path.*).
- `ocsp.*`: parseOcspResp, basicResponse (lazy), getOcspResponses, findOcspResponseForCert, verifyValidityAndStatus, createCertId, certIdEquals,
  jdkX500Equal (JDK X500Principal, order-sensitive; only for OCSP authorisation step 3), jdkRfc2253 (fault-string DN), javaOffsetDateTime.
- `binding.verifySignerName(trust, signer, cert, now)` (S3), `subjectName`, `memberEquals`; `profiles`: registry keyed by the certificateProfileInfo class name, Basic only.
- Added to src/trust/x500.ts: the exports `rdnValueToString` (BC IETFUtils.valueToString) and `asn1StringValue`.

## Findings (verified against the Java source or by probe)
- **BC getRDNValue order (probed with the jar, JDK 21 + BC 1.84):** `new X500Name(principal.getName())` keeps the JDK RFC 2253 order, which is reverse DER order.
  So the "first" businessCategory/serialNumber is the **last** one in DER order. For a multi-valued RDN, BC returns that RDN's first AVA, which may have another type.
  JDK `X500Principal.equals` is case-insensitive and order-sensitive (probe: `CN=a,O=b` != `O=b,CN=a`).
- The JDK emits unknown attribute types as `OID=#hexDER` (e.g. `2.5.4.15=#0c03676f76`). The jar's fault strings contain exactly that ("Unable to find OCSP response for certificate 2.5.4.15=#0c03676f76,2.5.4.5=#13…,CN=…").
- **OCSP messages** use `TimeUtils.toOffsetDateTime` → OffsetDateTime.toString in UTC, e.g. `2026-09-28T17:47:13Z` (seconds dropped when :00 and no millis). REVOKED uses `%tF %tT`.
- **CertID equality** is BC ASN.1 equality: the SHA-1 AlgorithmIdentifier with NULL params; absent params != NULL (in favour of BC parity).
- getOcspCerts in Java parses the embedded certs eagerly. The port parses them only after the globalconf candidates fail (tamper ocsp-embedded-cert-byte-changed → ok either way).
  The only divergence is an UNPARSABLE embedded cert when a globalconf cert matches.
- The OcspVerifier constructor (ocspFreshnessSeconds) runs after the response is found. Missing responseBytes, a non-basic type, or no SingleResponse → internal_error (prefixed invalid_cert_path.).
- getExtraCertificates is evaluated before getCaCert, unprefixed. Real containers have no CompleteCertificateRefs.
- PKIX: every EE failure (expiry, signature, unknown critical extension, RSA < 1024) → `cannot_create_cert_path.internal_error` "unable to find valid certification path to requested target".
  The exact JDK message and critical-extension set are UNCONFIRMED (never seen in the containers checked against the jar).
- Key-usage ("is not a signing certificate") is already in src/xades/cert.ts getSigningCertificate. It is not duplicated; binding's getSubjectName re-check gives internal_error.

## Notes
- Verified: `primitiveBytes(BitString)` drops the unused-bits octet (OCSP signatures verify on real containers; the unit test checks the length).
- The PKIX JDK message and critical-extension set are still UNCONFIRMED (no real or tampered case). The unit tests pin the port's behaviour.
- `getRdnValue` escapes per RFC 2253, so a serialNumber of `" "` becomes `"\ "` (not blank → no ClientId error). That matches BC valueToString.
