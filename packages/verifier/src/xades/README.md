# src/xades: ds:Signature / XAdES

Pure functions that port Santuario 4.0.4 (secure validation) as X-Road 7.8.3 uses it.
The behaviour, with source citations, is in SANTUARIO-RULES.md. Each file lists its fault codes at the top.

| File | What | Pipeline step (docs/architecture.md) |
|---|---|---|
| model.ts | `checkSignatureElement` (the `SignatureHooks` hook for `loadSignatureDocument` / `readContainer`), `readSignatureModel` (cached), and `referenceAt`, the lazy Reference ctor | V2 |
| references.ts | `checkRequiredReferences`, `isBatchSignature`, `checkMessagePartsReferenced` (these build References lazily, as `Signature.references` does) | V5, S1 |
| cert.ts | `getSigningCertificate`: the KeyInfo X509Certificate resolver, then the keyUsage nonRepudiation check | S2 |
| signature-value.ts | `verifySignatureValue(sd, container, cert)`, the checkSignatureValue port (resolvers: IdResolver, then the ASiC resolver). `getSignatureValueBytes(sd)` gives the stamped data for a non-batch timestamp | S4, V6 |
| crypto.ts | The WebCrypto SignatureMethods (RSA PKCS#1, RSA-PSS, ECDSA) | S4 |
| base64.ts | `decodeDsBase64` (the JDK MIME decoder, with its IllegalArgumentException cases) and `dsText` (Text children only) | all |

How to compose them: `loadSignatureDocument(xml, { checkSignatureElement })` → `readSignatureModel(sd.signature)`.
Then run, in order:
1. `checkRequiredReferences`
2. timestamp: `getSignatureValueBytes(sd)` for non-batch
3. `isBatchSignature` ? `verifySignatureHashChain` : `checkMessagePartsReferenced`
4. `getSigningCertificate`
5. binding
6. `verifySignatureValue`

Port deviations (none occur in real X-Road containers):
- SignatureMethods that Santuario knows but we do not implement (DSA, HMAC, rsa-sha224, …) give malformed_signature at load.
- An exclusive or 1.1 c14n of SignedInfo gives internal_error.
- Reference Transforms give internal_error.
- Digests other than SHA-1/256/384/512 give internal_error.
- KeyInfo RetrievalMethod and PEM-armoured certificates are not supported. They give "does not contain signing certificate" and internal_error respectively.

Tests: test/xades (unit tests per rule).
