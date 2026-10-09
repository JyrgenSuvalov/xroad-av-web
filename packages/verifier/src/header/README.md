# header/ — X-Road message header parsing

Research notes (verified in X-Road 7.8.3 source).

## getSigner (ACV:265-289)
- SOAP parse OK and SoapMessageImpl → request ? client : service.clientId.
- SOAP Fault body → SoapFault → "Unexpected SOAP" internal_error → **swallowed → signer null**.
- CodedException with code `invalid_soap` → REST fallback; any REST failure → `internal_error` "Invalid message" (thrown at V3).
- Any other CodedException → swallowed → signer null (port: internal_error at S3).

## SOAP (SaxSoapParserImpl, streaming SAX)
- invalid_soap only from: not well-formed / DOCTYPE (SAXException→SOAPException) or root ≠ {http://schemas.xmlsoap.org/soap/envelope/}Envelope.
- Port uses DOM: not-well-formed → invalid_soap. DEVIATION: SAX would raise a handler error
  (e.g. duplicate header field) before reaching a later well-formedness error; both are edge cases.
- Envelope children by QName: soap:Header (header handler), soap:Body (body handler); others ignored.
- Header children (ns http://x-road.eu/xsd/xroad.xsd): id, userId, issue, protocolVersion, client, service,
  securityServer, requestHash, (repr:representedParty). Duplicate → duplicate_header_field.
- Value = direct character data of the element (children's text not included).
- protocolVersion must start with "4." else invalid_protocol_version.
- client: @id:objectType (ns http://x-road.eu/xsd/identifiers) MEMBER|SUBSYSTEM (missing/unknown/unexpected → invalid_xml);
  children id:xRoadInstance, memberClass, memberCode, subsystemCode; ClientId.Conf.create: blank required → IAE; subsystem if non-null must be non-blank.
- service: objectType SERVICE; + serviceCode, serviceVersion; serviceCode required non-blank.
- securityServer: objectType SERVER; xRoadInstance, memberClass, memberCode, serverCode.
- Envelope close (only if no Fault): header present (missing_header); protocolVersion, client, id, service present
  (missing_header_field); Body present (missing_body); Body has element child (invalid_body);
  second non-Fault body child → invalid_body; serviceName.startsWith(serviceCode) else inconsistent_headers.
- isResponse: body first child local name endsWith "Response".

## REST (RestMessage.of)
- empty → error; first byte '1'..'9' → response else request. Lines: Java readLine (\n, \r, \r\n), UTF-8 lenient.
- Request: line1 Verb.valueOf exact (DELETE GET HEAD OPTIONS PATCH POST PUT TRACE); line2 java.net.URI, no scheme/authority;
  rawPath.split("/",8) ≥7 parts, parts[1] = "r<digit>" and digit == 1; ServiceId from parts 2..6 (percent-decoded, non-blank).
  Every remaining line is a header (empty line → error). For each header in order: x-road-client → decodeClientId (split("/",5), 3–4 parts);
  x-road-security-server → split("/",5) exactly 4; x-road-represented-party → split("/") (trailing empties dropped) ≤2.
  Any decode error fails the whole message. Sender = last x-road-client (null if absent → null signer).
- Response: line1 Integer.parseInt; line2 reason; headers; x-road-request-hash (lenient base64), x-road-service (split("/",6) == 5 parts),
  x-road-client decoded if present; x-road-id and request-hash must be non-empty. Sender = service.clientId (SUBSYSTEM).
- Header split: must contain ':'; name before first ':'; value after, no trim; hop-by-hop names → error.
- Segment decode (UriUtils): raw chars [A-Za-z0-9-._~!$&'()*+,;=:@] or %HH; else error; decoded bytes as UTF-8.

## Implementation
Files: `ids.ts` (ClientId/ServiceId/SecurityServerId, Java validation, XRoadId toString),
`soap.ts` (DOM port of SaxSoapParserImpl), `rest.ts` (RestMessage/RestRequest/RestResponse + UriUtils + java.net.URI subset),
`index.ts` (public API, re-exported from `src/index.ts`).

```ts
parseMessage(container: AsicContainer | string): ParsedMessage   // never throws
interface ParsedMessage {
  kind: 'soap' | 'rest';                 // 'rest' = the REST fallback ran (whether or not it succeeded)
  direction: 'request' | 'response' | null;
  header: MessageHeaderView;             // display strings only (UI message view)
  expectedSigner: ClientId | null;
  expectedSignerId: string | null;       // e.g. "SUBSYSTEM:EXAMPLE/GOV/1234567/consumer"
  signerError?: { faultCode: 'internal_error'; faultString; thrown: boolean; cause?: {faultCode, faultString} };
}
```
**Verifier contract:**
- `signerError.thrown === true`: Java getSigner throws internal_error "Invalid message" (REST fallback failed, or a SOAP
  response whose service has a blank subsystem). Fail at the signer-derivation step (V3).
- `signerError.thrown === false`: Java returns null (swallowed SOAP error, SOAP Fault, REST request without X-Road-Client).
  Continue; fail with internal_error at the S3 position (the NPE), so earlier-step failures win.
- Otherwise compare the certificate binding against `expectedSigner` and report `expectedSignerId` as `signer.id`.

Signer: SOAP request → header client; SOAP response → `service.getClientId()` (keeps the subsystem: MEMBER or SUBSYSTEM);
REST request → last X-Road-Client; REST response → client part of x-road-service (always SUBSYSTEM).

`MessageHeaderView` fields (all optional strings): client, service, queryId, userId, issue, protocolVersion,
securityServer, representedParty (`class/code`), requestHash, requestHashAlgorithm, serviceName (SOAP body element),
verb, path, query (REST request), status, reason (REST response), requestId, and restHeaders
(`{name, value}[]` in message order). On a swallowed SOAP error, the fields parsed before the error are still present.

The derived signer ID matched the jar's on real SOAP and REST requests and responses. Unit tests: `test/header/header.test.ts`.

Known deviations (the outcome is internal_error either way; only the cause message differs):
- DOM vs SAX: a handler error before a later well-formedness error → Java swallows it (null), we report invalid_soap → REST → thrown.
- Integer.parseInt accepts non-ASCII Unicode digits; we accept only ASCII.
- java.net.URI is emulated only as far as RestRequest needs it (scheme/authority/illegal characters/escapes).
