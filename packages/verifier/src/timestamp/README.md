# src/timestamp: RFC 3161 timestamp

Port of `AsicContainerVerifier.getTimeStampToken` + `TimestampVerifier.verify`
(X-Road 7.8.3, BC 1.84).

## API

```ts
const token = parseTimestampToken(container.timestampDer);   // may throw io_error / internal_error
// ... pipeline computes stampedData (see below) ...
const { genTime, tsaCert } = await verifyTimestampToken(token, stampedData, trust, now);
// or both at once: verifyTimestamp(tokenDer, stampedData, trust, now)
```

`genTime` is `atDate` for the signing-cert and OCSP checks. `tsaCert` is the approved
TSA cert from the global configuration (`timestamp.signedBy`). Certs inside the token are never used.
`now` is wall-clock time, used only for the visibility filter of non-main instances.

## Pipeline order

Java builds the token **before** computing the stamped data, so:
1. `parseTimestampToken(container.timestampDer)`: the token parse errors come first.
2. Stamped data (`getTimestampedData`):
   - batch (`ts-hashchainresult.xml` present): verify the ts hash chain (src/hashchain; any failure →
     `malformed_signature` "Failed to verify time-stamp hash chain: …"), then
     stampedData = `container.getBytes('ts-hashchainresult.xml')`;
   - embedded: stampedData = base64-decoded `ds:SignatureValue` (lenient: whitespace ignored).
3. `verifyTimestampToken(token, stampedData, trust, now)`.

## Fault codes

| Condition | Code |
|---|---|
| outer BER does not decode / trailing bytes | `io_error` |
| empty token; not ContentInfo/SignedData; eContentType ≠ TSTInfo; signers ≠ 1; TSTInfo bad; no ESS signingCertificate(V2) | `internal_error` |
| imprint algorithm unsupported | `internal_error` |
| imprint ≠ H(stampedData) | `malformed_signature` "Timestamp hashes do not match" |
| no approved TSA in visible instances | `mlog.no_timestamping_provider_found` |
| no approved TSA matches the SID (BC SignerId.match, BC X500 rules) | `mlog.tsp_certificate_not_found` |
| BC SignerInformation.verify fails (signingTime outside cert validity, content-type, message-digest, cmsAlgorithmProtect, countersignature placement, signature) | `mlog.timestamp_signer_verification_failed` |

`mlog.timestamp_token_signer_info_not_found` is unreachable (the only SignerInfo always matches its own SID).

## Known divergences from BC (unreachable with conforming TSAs)

- Digests: SHA-1/256/384/512 only (WebCrypto). SHA-224/SHA-3/etc. imprint → `internal_error`; as the SignerInfo digest → signer-verification failure. BC accepts these.
- Signatures: RSA PKCS#1 v1.5, RSA-PSS (MGF1 with the same hash), ECDSA P-256/384/521. No DSA/EdDSA.
- Signed attributes are re-sorted into DER SET order (as BC's `getEncoded(DER)`), but each attribute is used as encoded (non-DER BER inside an attribute is not normalised).
- The outer parse uses asn1js, whose leniency differs from BC's ASN1InputStream in exotic encodings.
- A genTime without a zone (local time) → `internal_error`. BC would use the JVM's default zone.
- Unsigned countersignatures are only checked for placement and a non-empty value set; BC also parses each as a SignerInfo.
