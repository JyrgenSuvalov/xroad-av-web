# Santuario xmlsec 4.0.4 — verification rules as used by X-Road 7.8.3 asicverifier

Source: `xmlsec-4.0.4-sources.jar` (Maven Central), unpacked under `src/`. Paths below are relative to
`src/org/apache/xml/security/`. "XSE" = XMLSecurityException, "XSigE" = XMLSignatureException (extends XSE).
Exception hierarchy: MissingResourceFailureException, ReferenceNotInitializedException extend XSigE;
ResourceResolverException, TransformationException, InvalidTransformException, InvalidCanonicalizerException,
CanonicalizationException, KeyResolverException extend XSE (not XSigE).

## 0. What X-Road calls (X-Road-7.8.3/src)

- `Signature.readSignature()` (common/common-message/.../signature/Signature.java:335-338):
  `new XMLSignature(signatureElement, BASE_URI)` — the **2-arg** ctor; `BASE_URI = null` (Helper.java:56).
  The 2-arg ctor delegates to `this(element, baseURI, true, null)` → **secureValidation = true**
  (signature/XMLSignature.java:494-497). No `secureValidation` / `maxReferences` / `ignoreLineBreaks` /
  `JCEMapper.setProviderId` configured anywhere in X-Road main code. `Init.init()` (Signature.java:81) →
  `dynamicInit()` since the `org.apache.xml.security.resource.config` property is unset (Init.java:75-97).
- signatureElement = first `ds:Signature` in document (missing → CodedException X_MALFORMED_SIGNATURE before
  Santuario is touched, Helper.java:269-276). Then `readObjectContainer()` builds `new ObjectContainer(first ds:Object)`.
- Signature(InputStream) ctor (Signature.java:114-124): `XMLSignatureException` → `X_MALFORMED_SIGNATURE`;
  **any other exception (plain XSE, DOMException, RuntimeException) → `XrdRuntimeException.systemException`**.
- Verification (globalconf-impl/.../signature/SignatureVerifier.java): `getSigningCertificate()` =
  `xmlSignature.getKeyInfo().getX509Certificate()` (null → X_MALFORMED_SIGNATURE "does not contain signing
  certificate"; no KeyInfo → `getKeyInfo()` returns null → **NPE**). `verifySignatureValue` (356-370) adds
  `IdResolver(document)` then the ASiC resolver (AsicContainerVerifier.java:190-209), then
  `checkSignatureValue(cert)`; false → X_INVALID_SIGNATURE_VALUE.
- IdResolver (common-message/.../IdResolver.java:47-57): canResolve = `context.attr.getValue().startsWith("#")`
  (**NPE if Reference has no URI attr**, because attr is null); resolve returns `new XMLSignatureNodeInput(elem)`
  or **null** if id not found.
- ASiC resolver: canResolve = attachment URI with known digest, or `asic.hasEntry(uri)`; returns
  `XMLSignatureDigestInput(base64(digest))` for attachments else `XMLSignatureStreamInput(entry)`.

## 1. XMLSignature(Element, baseURI, secureValidation) — signature/XMLSignature.java:540-632

1. `ElementProxy(element, baseURI)` (utils/ElementProxy.java:85-96): null element → XSE
   "ElementProxy.nullElement". `guaranteeThatElementInCorrectSpace` (239-253) throws XSE only if BOTH namespace
   AND local name differ (lax; `&&`).
2. Element itself must be `{http://www.w3.org/2000/09/xmldsig#}Signature` (ns + localName) else **XSigE**
   "signature.Verification.InvalidElement" (543-548).
3. First *element* child (text/comments/PIs skipped by `XMLUtils.getNextElement`, utils/XMLUtils.java:140-146)
   must be ds:SignedInfo (ns + localName) else **XSigE** "xml.WrongContent" (551-559).
4. `new SignedInfo(...)` (562) — see §2.
5. Next element sibling must be ds:SignatureValue else **XSigE** "xml.WrongContent" (567-576). Its `Id` attr is
   registered as ID (`setIdAttributeNode`, 577-580). Content is NOT decoded here (lazy, §4).
6. Next element: if ds:KeyInfo → `new KeyInfo(el, baseURI)` (no structural checks, registers Id;
   keys/KeyInfo.java ctor) + `setSecureValidation(sv)` (586-594). KeyInfo optional.
7. Every remaining element sibling must be ds:Object else **XSigE** "signature.Verification.InvalidElement"
   (597-606). So: KeyInfo after an Object, a second KeyInfo, or any foreign element → XSigE.
8. For each ds:Object: register `Id`; for each *direct element child* with localName `Manifest` (ANY namespace)
   → `new Manifest(child, baseURI)` (secureValidation=true via 2-arg ctor, signature/Manifest.java:100-103);
   localName `SignatureProperties` (any ns) → `new SignatureProperties` (registers its Id and ds:SignatureProperty
   Ids; signature/SignatureProperties.java ctor). (608-625). Manifest rules = §3 (0 refs → DOMException!).
9. No check for duplicate Ids anywhere; `setIdAttributeNode` just marks attributes as ID type.

## 2. SignedInfo — signature/SignedInfo.java:237-262

- `super(element, baseURI, secureValidation)` = Manifest ctor (§3) runs FIRST: References are counted
  (`selectDsNodes` over ALL element children named ds:Reference, wherever they sit), 0 → DOMException,
  >30 → plain XSE "signature.tooManyReferences".
- First element child must be ds:CanonicalizationMethod else **XSigE** "xml.WrongContent" (244-250).
- Next element must be ds:SignatureMethod else **XSigE** "xml.WrongContent" (252-258).
- Any other/unknown elements after SignatureMethod are ignored (only ds:Reference are picked up).
- `new SignatureAlgorithm(signatureMethod, baseURI, sv, provider)` (algorithms/SignatureAlgorithm.java:147-166):
  - sv && URI ∈ {`xmldsig-more#rsa-md5`, `xmldsig-more#hmac-md5`} → plain **XSE** "signature.signatureAlgorithm" (157-163).
  - unknown/empty Algorithm URI → **XSigE** "algorithms.NoSuchAlgorithmNoEx" at CONSTRUCTION (172-180).
  - JCA `Signature.getInstance` failure → XSigE "algorithms.NoSuchAlgorithm" (SignatureBaseRSA.java:66-86).
  - `engineGetContextFromElement` parses params (HMACOutputLength / RSAPSSParams) at construction.
- CanonicalizationMethod Algorithm is NOT validated at construction. Unknown/empty c14n URI →
  `InvalidCanonicalizerException` from `Canonicalizer.getInstance` (c14n/Canonicalizer.java:102-114) thrown at
  `checkSignatureValue` time (`signInOctetStream`, SignedInfo.java:326-345), wrapped into XSigE (XMLSignature.java:916-917).
  Supported: c14n 1.0 ±comments, exc-c14n ±comments, c14n 1.1 ±comments, physical.
- For exc-c14n, an `InclusiveNamespaces PrefixList` child of CanonicalizationMethod is honoured (getInclusiveNamespaces).
- **No re-parsing** of SignedInfo in 4.0.4 — SignedInfo DOM subtree is canonicalized directly
  (`canonicalizeSubtree(getElement())`), so inherited ns from ancestors apply per chosen c14n.

## 3. Manifest / Reference

Manifest ctor (signature/Manifest.java:112-161): registers Manifest Id; refs = ds:Reference element children.
- 0 refs → **`org.w3c.dom.DOMException` (RuntimeException!)** WRONG_DOCUMENT_ERR "xml.WrongContent" (130-137).
- sv && count > `referenceCount` (default `MAXIMUM_REFERENCE_COUNT = 30`, sysprop
  `org.apache.xml.security.maxReferences`, 58-65) → plain **XSE** "signature.tooManyReferences" (139-143). 31 refs fail; 30 OK.
- Registers each Reference's `Id` attr as ID (149-156). References are NOT parsed here (list filled with null).

Reference objects are created lazily in `verifyReferences` (Manifest.java:307-413) — i.e. only during
`checkSignatureValue`, AFTER the signature value verified. Reference ctor (signature/Reference.java:242-275):
- Optional first element ds:Transforms → `new Transforms` (0 ds:Transform children → TransformationException);
  sv && >5 transforms (`MAXIMUM_TRANSFORM_COUNT = 5`, :116) → plain XSE "signature.tooManyTransforms".
- Next element must be ds:DigestMethod else plain XSE "signature.Reference.NoDigestMethod" (262-266).
- Next element must be ds:DigestValue else plain XSE "signature.Reference.NoDigestValue" (268-273).
- Trailing elements after DigestValue are ignored. URI attribute may be absent (no check in Santuario;
  but X-Road's IdResolver NPEs on it). Type attribute only matters for followManifests (false by default, XMLSignature.java:244).
- Transform Algorithm empty → TransformationException; unknown → InvalidTransformException — both only when
  `Transforms.item(i)` is called during digesting (transforms/Transforms.java:306-313, Transform.java:157-170).

Reference.verify() (Reference.java:785-800): (1) `getDigestValue()` decodes DigestValue (§4) FIRST,
(2) `calculateDigest(true)`, (3) `MessageDigest.isEqual(elemDig, calcDig)` (byte compare, length-sensitive);
mismatch → returns false (logged), no exception.

calculateDigest (Reference.java:696-738):
1. `getContentsBeforeTransformation()` (430-444): `ResourceResolver.resolve(perManifestResolvers, ctx)`
   (utils/resolver/ResourceResolver.java): per-manifest resolvers in insertion order (IdResolver, then ASiC),
   **first whose canResolve is true wins — its return value is used even if null**; then global resolvers
   (ResolverFragment, ResolverXPointer — dynamicInit registers only these two, ResourceResolver.java:130-139);
   none → ResourceResolverException "utils.resolver.noClass" → ReferenceNotInitializedException →
   Manifest wraps as **MissingResourceFailureException** (Manifest.java:403-409) → propagates (is an XSigE).
2. If resolver returned **null** → `input.getPreCalculatedDigest()` → **NullPointerException** (699), escapes
   checkSignatureValue uncaught (only XSE is caught there).
3. If `input.getPreCalculatedDigest() != null` (XMLSignatureDigestInput) → return
   `XMLUtils.decode(preCalcBase64)` (748-757) — **DigestMethod is never consulted** (unknown/MD5 digest URI
   irrelevant for such refs) and comparison is on decoded BYTES, not base64 strings.
4. Else `getMessageDigestAlgorithm()` (285-303): empty Algorithm → returns null → **NPE** at `mda.reset()`;
   sv && `xmldsig-more#md5` → **XSigE** "signature.signatureAlgorithm"; unknown URI → XSigE
   "algorithms.NoSuchMap" (MessageDigestAlgorithm.java:102-108). These are thrown OUTSIDE the try → propagate as
   XSigE (not wrapped as MissingResource). Registered digests: md5, sha1, sha224, sha256 (xmlenc#sha256),
   sha384, sha512 (xmlenc#sha512), ripemd160, whirlpool, sha3-224/256/384/512.
5. Transforms/c14n/IO failures inside the try → ReferenceNotInitializedException (736) → MissingResourceFailureException.

verifyReferences loop: does NOT short-circuit on a false reference — later references are still constructed and
digested; any exception in any reference aborts the whole call. Result = AND of all.

## 4. Base64 decoding (SignatureValue, DigestValue, X509Certificate, precomputed digest)

- Text = concatenation of direct child **Text** nodes only (`XMLUtils.getFullTextChildrenFromNode`,
  XMLUtils.java:277-289): CDATA sections / nested elements' text are NOT included (DOM-parser dependent: a CDATA
  node is CDATA_SECTION_NODE ≠ TEXT_NODE unless the parser coalesces).
- Decoder = `java.util.Base64.getMimeDecoder()` (XMLUtils.java:524-526) — lenient:
  any char outside the base64 alphabet (whitespace, line breaks, `*`, `!`, …) is **silently ignored**;
  missing padding accepted; unused trailing bits not checked. Throws **IllegalArgumentException
  (RuntimeException)** for: a single dangling base64 char in the last quantum; `=` at a quantum boundary
  (e.g. `"AAAA="`, or empty `"="`); `xx=` not followed immediately by `=` (`"QQ=A"`, also `"QQ= ="`);
  base64 alphabet chars after the padding. (JDK java.util.Base64.Decoder.decode0 semantics.)
- SignatureValue decoded lazily in checkSignatureValue (`getSignatureValue`, XMLSignature.java:670-673);
  DigestValue in Reference.getDigestValue (Reference.java:765-776). IAE escapes as RuntimeException
  (X-Road → systemException-ish, not X_INVALID_SIGNATURE_VALUE). Empty text → empty byte[] (no error).

## 5. KeyInfo.getX509Certificate() — keys/KeyInfo.java:913-982

- Internal (per-KeyInfo) resolvers first (none in X-Road), then static `KeyResolver` list, in order
  (keys/keyresolver/KeyResolver.java registerDefaultResolvers): RSAKeyValue, DSAKeyValue, **X509Certificate**,
  X509SKI, RetrievalMethod, X509SubjectName, X509IssuerSerial, DEREncodedKeyValue, KeyInfoReference,
  X509Digest, ECKeyValue.
- Outer loop = resolver, inner loop = KeyInfo element children in document order, storage list = `[null]`
  (KeyInfo.java:92-100,962-982). First non-null wins. *KeyValue resolvers return null for certificates.
- X509CertificateResolver (keys/keyresolver/implementations/X509CertificateResolver.java): applies to ANY
  child in the ds namespace; takes the ds:X509Certificate *direct children* of that child (i.e. of ds:X509Data);
  if none, recurses into a nested ds:X509Data child; first X509Certificate in document order wins
  (across X509Data elements, the first X509Data containing an X509Certificate wins).
- Cert parse: `XMLUtils.decode(text)` + `CertificateFactory("X.509").generateCertificate`
  (keys/content/x509/XMLX509Certificate.java:99-108). Broken DER → CertificateException → XSE → resolver wraps as
  **KeyResolverException** (aborts; a later valid cert is NOT tried). Broken base64 → **IllegalArgumentException**
  escapes. (JDK: PEM-armoured content is also accepted; trailing bytes after the DER are ignored.)
- X509SKI/SubjectName/IssuerSerial/Digest need a StorageResolver → null with storage=null.
- RetrievalMethod (implementations/RetrievalMethodResolver.java:129-169): only reached if no X509Certificate found.
  Resolves URI via GLOBAL resource resolvers only (Fragment/XPointer; `#id` in same doc; `file:`/`http:` refused by
  `isURISafeToResolve`), Type rawX509Certificate → DER parse; else applies resolvers to referenced element;
  sv forbids RetrievalMethod→RetrievalMethod; all errors swallowed → null.
- No X509 material → returns **null** (X-Road → X_MALFORMED_SIGNATURE). No KeyInfo element → NPE in X-Road.

## 6. checkSignatureValue(cert) — XMLSignature.java:845-919

null cert → XSigE. Then with `pk = cert.getPublicKey()`:
1. `sa.initVerify(pk)` (892) — wrong key type → XSigE (SignatureAlgorithmSpi.java:178-195, InvalidKeyException).
2. `si.signInOctetStream(bos)` (896) — canonicalize SignedInfo with its CanonicalizationMethod; unknown c14n →
   InvalidCanonicalizerException → wrapped XSigE.
3. `getSignatureValue()` (898) — MIME base64 decode (IAE possible).
4. `sa.verify(sigBytes)` (908) — false → **return false immediately; references are NOT dereferenced/digested**.
5. Only if valid: `si.verify(followManifests=false)` (913) → Manifest.verifyReferences (§3). Returns false on
   digest mismatch; MissingResourceFailureException / XSigE / NPE / IAE as described.
Catch: XSigE rethrown; other XSE wrapped as XSigE (914-918); RuntimeExceptions escape.

Algorithms (JCA provider: default — X-Road only *appends* BouncyCastle, so SunRsaSign/SunEC win):
- `xmldsig-more#rsa-sha512` → `Signature.getInstance("SHA512withRSA")` (JCEMapper.java:145-147), standard
  PKCS#1 v1.5. Sun impl throws SignatureException on length ≠ modulus length → XSigE (SignatureBaseRSA.java:102-109).
- ECDSA (`xmldsig-more#ecdsa-sha*`): `SHA256withECDSA` etc. (DER). SignatureValue must be **raw r||s**;
  `convertXMLDSIGtoASN1` (ECDSAUtils.java:112-165) splits at `len/2` (odd length: last byte ignored, no check
  vs curve size; empty → ArrayIndexOutOfBounds), strips leading zeros, builds DER; >255 → IOException → XSigE.
- RSA-PSS `2007/05/xmldsig-more#shaXXX-rsa-MGF1`: fixed `PSSParameterSpec(SHA-XXX, MGF1, MGF1(SHA-XXX),
  saltLen = hash length (20/28/32/48/64), trailer 1)`, JCA "RSASSA-PSS" (SignatureBaseRSA.java:371-579);
  any params in SignatureMethod are ignored. Generic `2007/05/xmldsig-more#rsa-pss` REQUIRES pss:RSAPSSParams
  (missing → XSigE "algorithms.MissingRSAPSSParams" at SignedInfo construction, :821-845); digest ∈
  {sha256, sha384, sha512}; SaltLength default = hash length; TrailerField default 1.

## 7. Digest input with no Transforms

- XMLSignatureNodeInput(element) from IdResolver: `write()` → `canonicalize(os, false)` →
  **`Canonicalizer20010315OmitComments`** (inclusive C14N 1.0, no comments; signature/XMLSignatureInput.java:461-470,
  XMLSignatureNodeInput.write). Subtree mode (CanonicalizerBase.java:134-185): `getParentNameSpaces` collects
  ancestor xmlns declarations AND the ancestors' own element-prefix namespaces; apex element renders all
  in-scope (inherited) ns decls that are visibly needed per inclusive c14n (i.e. all in-scope, except default
  xmlns="" suppression) plus inherited `xml:*` attributes (Canonicalizer20010315.java:139-186, 315-350).
  Same bytes as `input.getBytes()`. (`excludeComments` flag not set by IdResolver, but the OmitComments
  canonicalizer drops comments anyway.)
- XMLSignatureStreamInput: raw bytes copied to the digester verbatim, stream closed after
  (XMLSignatureStreamInput.write). A null stream → writes nothing → digest of empty input.
- XMLSignatureDigestInput: no hashing; precomputed base64 decoded and compared (§3.3).
- URI="" via ResolverFragment: whole Document, comments excluded, inclusive c14n.

## 8. With Transforms (short)

- `Transforms.performTransforms` (Transforms.java:253-286): sv forbids XSLT (TransformationException
  "ForbiddenTransform"); others: base64, c14n 1.0/1.1/exc ±comments, XPath, XPath2 filter, enveloped-signature.
- Last transform writes directly into the digest stream; if result is a node-set that still needs bytes, it is
  serialized with inclusive C14N 1.0 omit comments (as §7). Octet input fed to a c14n/xpath transform is parsed
  as XML (secure parser) first. Enveloped-signature removes the ds:Signature ancestor of the Transform element
  from the node-set. Transform failures → ReferenceNotInitializedException → MissingResourceFailureException.

## 9. Other secure-validation effects that can bite

- >30 References in SignedInfo or in any ds:Object/*:Manifest → plain XSE at XMLSignature construction
  (X-Road: systemException, not X_MALFORMED_SIGNATURE). 0 References → DOMException (RuntimeException).
- >5 Transforms per Reference → XSE (at verify time). XSLT forbidden.
- rsa-md5 / hmac-md5 SignatureMethod → XSE at construction; md5 DigestMethod → XSigE at digest time
  (skipped for precomputed-digest references).
- ResolverFragment under sv: `#id` must be unique in the doc (`protectAgainstWrappingAttack`, XMLUtils.java:862)
  else ResourceResolverException "MultipleIDs" — NOT relevant to X-Road since IdResolver claims every `#…` URI first.
- `isURISafeToResolve`: `file:`/`http:` URIs refused (only for RetrievalMethod path; References only go through
  resolver canResolve checks — no global file/http resolvers are registered by dynamicInit anyway).
- RetrievalMethod→RetrievalMethod forbidden (returns null).
- Element/attribute order: SignedInfo children (C14NMethod, SignatureMethod) and Signature children (SignedInfo,
  SignatureValue, KeyInfo?, Object*) are strictly ordered by element siblings; whitespace/comments between are fine.
