# Architecture

The verifier is a TypeScript port of X-Road's `asicverifier` 7.8.3. It answers the same question as the CLI: was this messagelog container signed by the member named in the message, with a certificate, OCSP response and timestamp that the X-Road instance's **global configuration** approves? The answer is given the same way: the same verdict, fault code and extracted details. Everything runs in the browser. Containers are never uploaded.

```
 browser                                           server (nginx or Vite dev)
┌──────────────────────────────────────────┐      ┌──────────────────────────────┐
│ apps/web (Svelte UI)                     │      │ /anchor.xml   (static file)  │
│   drop zone → verifyContainer() → verdict│      │ /globalconf/* (pass-through  │
│   trust panel ← ConfPoller               │◀────▶│   proxy, allow-listed paths) │──▶ X-Road central server
│                                          │      └──────────────────────────────┘
│ packages/verifier (@xrav/verifier)       │
│   globalconf: anchor → signed directory  │
│     → shared-params → TrustContext       │
│   verify: container → VerificationResult │
└──────────────────────────────────────────┘
```

## Trust model

- **The configuration anchor is the only input.** It is supplied when the app is deployed (mounted into the container, or `ANCHOR_PATH` in dev), not chosen by the person verifying. It names the central server (`downloadURL`) and the certificates that sign the configuration directory.
- **The proxy is not trusted.** It only exists because browsers can't fetch the central server cross-origin. It holds no state and does no verification. The browser checks the directory signature against the anchor and the shared-params hash against the directory, so a tampered proxy or upstream is detected.
- **The trust context comes only from verified shared-params:** the approved CAs (with certificate profile and OCSP responders), the approved TSAs, and `ocspFreshnessSeconds`. The member list is not used.

## Global configuration (`packages/verifier/src/globalconf/`)

1. `loadAnchor` fetches `/anchor.xml`; `parseAnchor` reads the instance identifier and each source's `downloadURL` and verification certificates.
2. `fetchVerifiedConf` fetches `/globalconf/<directory path>?version=6`. It steps down to lower versions only on 404, as X-Road's confclient does.
3. `verifyDirectory` splits the MIME directory, picks the anchor certificate whose SHA-512 matches `Verification-certificate-hash`, and verifies the signature over the exact signed bytes with WebCrypto. Only then is the inner part parsed (`Expire-date`, `Version`, part hashes).
4. `shared-params.xml` is fetched from its `Content-location`, checked against the hash in the directory, and parsed (`parseSharedParams`). Certificates may be base64(DER) or base64(PEM text); both are accepted.
5. `instanceTrust` and `buildTrustContext` turn it into a `TrustContext`.
6. `ConfPoller` repeats this every 60 s. An expired configuration is still used: like `asicverifier`, verification doesn't check configuration expiry. The UI shows it as amber instead. A failed directory signature is a hard failure.

## Container verification (`verifyContainer`, `src/verify.ts`)

`verifyContainer(bytes, trust)` never throws; it returns either the details or `{ ok: false, faultCode, faultString }`. The steps run in X-Road's exact order, because the order decides which fault code a broken container gets. Step names follow `AsicContainerVerifier`/`SignatureVerifier`.

| Step | What | Module |
|---|---|---|
| read | Unzip with size and entry limits, check the ASiC entries (`mimetype`, `message.xml`, `META-INF/signatures.xml`, …) | `container`, `xml` |
| V2 | Parse `signatures.xml` (hardened XML: no DTDs or entities) into the `ds:Signature` model, with Santuario's structural checks | `xml`, `xades` |
| V3 | Derive the expected signer from `message.xml`: SOAP `client` (request) or service owner (response); REST `X-Road-Client` / `x-road-service` | `header` |
| V5 | The signature must reference `/message.xml` or `/sig-hashchainresult.xml` | `xades` |
| V6 | Timestamp: parse the RFC 3161 token (`timestamp.tst` or embedded XAdES), compute the stamped data (batch: verify the timestamp hash chain), verify against an approved TSA. Its genTime becomes the validation time | `timestamp`, `hashchain` |
| S1 | Batch signature: verify the signature hash chain and the attachment digests. Single signature: `message.xml` must be covered | `hashchain`, `xades` |
| S2 | Signing certificate from KeyInfo (needs nonRepudiation) | `xades` |
| S3 | Signer binding: decode the member from the certificate with the CA's certificate profile and compare it with the signer from V3 | `binding` |
| S4 | Signature value and reference digests (inclusive C14N 1.0, Santuario byte-exact) | `c14n`, `xades` |
| S6 | Certificate path to an approved CA and the OCSP response at genTime (freshness, status, responder) | `certpath`, `ocsp` |
| V9 | Result: signer ID, certificate summaries in the JDK's RFC 2253 format, OCSP producedAt, timestamp genTime, attachment digests | `result` |

Lower-level helpers: `trust` (X.509, BouncyCastle-style X.500 name matching, WebCrypto signature checks) and `util` (bytes, the `CodedError` / X-Road error-code model).

Some behaviour follows from the order and is intentional parity:
- The timestamp is checked before anything about the signature.
- With a single signature, changing the client in `message.xml` gives `incorrect_certificate` (S3) rather than `invalid_signature_value` (S4).
- With a batch signature, an edited attachment gives `ok: true` with that attachment marked `verified: false`, as the jar does. The UI highlights it.

## Web app (`apps/web/`)

Svelte 5, built by Vite into static files. `lib/trust.svelte.ts` wraps `ConfPoller` for the trust panel. The drop zone reads the file locally and calls `verifyContainer`. `lib/messageView.ts` turns `message.xml` into the header fields and body shown next to the verdict. Attachments are only offered as downloads, never rendered. The nginx image adds a strict CSP (see [docker/README.md](../docker/README.md)).

## Testing

`pnpm test` covers each stage with synthetic inputs: hand-built containers, signatures, certificates, OCSP responses and timestamp tokens, plus global configuration vectors derived from X-Road's own system-test fixture. Parity with the 7.8.3 jar was established separately, by running the jar and this port over the same set of real and tampered containers. That set isn't part of the repository.

## Known deviations from the jar

- **Fault strings.** The fault code always matches; a few fault strings differ in wording only: the `[<uuid>] [SYSTEM]` prefix on nested hash-chain errors is omitted, `EncapsulatedTimeStamp` is named with its `xades:` prefix, a Java NPE message is replaced by "Cannot derive the signer from the message (signer is null)", and ASN.1 parse errors use asn1js's wording.
- **Algorithms WebCrypto lacks.** Digests other than SHA-1/256/384/512 give `internal_error`. Signature methods other than RSA PKCS#1 v1.5, RSA-PSS and ECDSA P-256/384/521 give `malformed_signature`. RSA-PSS and ECDSA are implemented but weren't checked against the jar; X-Road containers use RSA-SHA512 / SHA-512.
- **Unsupported XML signature features.** Exclusive C14N, C14N 1.1 and Reference Transforms give `internal_error`; KeyInfo `RetrievalMethod` isn't followed. X-Road doesn't produce these.
- **Rare edge cases**, none of which conforming X-Road components produce:
  - asn1js is more or less lenient than BouncyCastle on some exotic encodings.
  - A timestamp genTime without a time zone gives `internal_error`; BouncyCastle would use the JVM's default zone.
  - Embedded OCSP responder certificates are parsed only if no global configuration certificate matches, so an unparsable embedded certificate next to a matching one passes here but fails in Java.
  - Malformed message headers give `internal_error` in both, but sometimes with a different cause message (the port parses SOAP with a DOM, X-Road with SAX).
  - Container entry names are matched exactly; Java ignores case.

## Source references

Comments in the code cite the X-Road 7.8.3 Java source as `ABBR:line`, relative to `src/` in the [X-Road repository](https://github.com/nordic-institute/X-Road/tree/7.8.3/src):

| Abbr | File |
|---|---|
| ACV | `lib/asic-core/src/main/java/ee/ria/xroad/common/asic/AsicContainerVerifier.java` |
| AC | `lib/asic-core/.../asic/AsicContainer.java` |
| AH | `lib/asic-core/.../asic/AsicHelper.java` |
| ACE | `lib/asic-core/.../asic/AsicContainerEntries.java` |
| AU | `lib/asic-core/.../asic/AsicUtils.java` |
| AVM | `tool/asic-verifier-cli/src/main/java/org/niis/xroad/asic/verifier/cli/AsicVerifierMain.java` |
| SV | `lib/globalconf-impl/src/main/java/org/niis/xroad/globalconf/impl/signature/SignatureVerifier.java` |
| TV | `lib/globalconf-impl/.../impl/signature/TimestampVerifier.java` |
| OV | `lib/globalconf-impl/.../impl/ocsp/OcspVerifier.java` |
| CCV | `lib/globalconf-impl/.../impl/cert/CertChainVerifier.java` |
| CCF | `lib/globalconf-impl/.../impl/cert/CertChainFactory.java` |
| CH | `lib/globalconf-impl/.../impl/cert/CertHelper.java` |
| GCI | `lib/globalconf-impl/src/main/java/org/niis/xroad/globalconf/impl/GlobalConfImpl.java` |
| VCD | `lib/globalconf-core/src/main/java/org/niis/xroad/globalconf/model/VersionedConfigurationDirectory.java` |
| SIG | `common/common-message/src/main/java/ee/ria/xroad/common/signature/Signature.java` |
| HLP | `common/common-message/.../signature/Helper.java` |
| IDR | `common/common-message/.../signature/IdResolver.java` |
| HCV | `common/common-message/src/main/java/ee/ria/xroad/common/hashchain/HashChainVerifier.java` |
| DL | `common/common-message/.../hashchain/DigestList.java` |
| XSD | `common/common-message/src/main/resources/hashchain.xsd` |
| MFN | `common/common-message/src/main/java/ee/ria/xroad/common/util/MessageFileNames.java` |
| SAX | `common/common-message/.../message/SaxSoapParserImpl.java` |
| RM | `common/common-message/.../message/RestMessage.java` |
| RREQ | `common/common-message/.../message/RestRequest.java` |
| RRES | `common/common-message/.../message/RestResponse.java` |
| ECS | `common/common-core/src/main/java/ee/ria/xroad/common/ErrorCodes.java` |
| CE | `common/common-core/.../common/CodedException.java` |
| XRE | `common/common-core/src/main/java/org/niis/xroad/common/core/exception/XrdRuntimeException.java` |
| ECE | `common/common-core/.../core/exception/ErrorCode.java` |
| XU | `common/common-core/src/main/java/ee/ria/xroad/common/util/XmlUtils.java` |
| EU | `common/common-core/.../util/EncoderUtils.java` |
| CU | `common/common-core/.../util/CertUtils.java` |

Santuario-specific rules (XML signature parsing and checks as X-Road uses them) are written up in [packages/verifier/src/xades/SANTUARIO-RULES.md](../packages/verifier/src/xades/SANTUARIO-RULES.md).
