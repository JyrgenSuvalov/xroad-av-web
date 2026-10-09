/**
 * X-Road message header parsing and signer derivation (port of
 * AsicContainerVerifier.getSigner, ACV:265-289).
 *
 *   parseMessage(containerOrText) → ParsedMessage   (never throws)
 *
 * Signer derivation outcomes, and what the verifier must do with them:
 *   - expectedSigner set, signerError undefined → use it (signer ID = clientIdToString)
 *   - signerError.thrown === true  → Java getSigner THROWS internal_error "Invalid message"
 *     (REST fallback failed). The verifier fails at the signer-derivation step (V3).
 *   - signerError.thrown === false → Java getSigner returns null (a swallowed SOAP error, a
 *     SOAP Fault, or a REST request without X-Road-Client). The verifier continues and
 *     fails with internal_error at the S3 position (NPE in Java), so earlier steps win.
 *
 * Which party is the signer (Java):
 *   SOAP request  → header client
 *   SOAP response → service.getClientId() (owner of the service: MEMBER or SUBSYSTEM)
 *   REST request  → last X-Road-Client header
 *   REST response → client part of x-road-service (always SUBSYSTEM)
 *
 * `header` holds display strings only (for the UI message view); undefined fields
 * were absent or could not be parsed.
 */
import type { AsicContainer } from '../container/read';
import { ENTRY_MESSAGE } from '../container/read';
import { CodedError, ErrorCodes } from '../util/errors';
import {
  clientIdToString,
  IdentifierError,
  securityServerIdToString,
  serviceClientId,
  serviceIdToString,
  type ClientId,
} from './ids';
import { parseRest, type RestParseResult } from './rest';
import { isResponseServiceName, parseSoap, type SoapParseResult } from './soap';

export type { ClientId, SecurityServerId, ServiceId } from './ids';
export { clientIdToString, securityServerIdToString, serviceIdToString } from './ids';

export interface MessageHeaderView {
  /** e.g. `SUBSYSTEM:EXAMPLE/GOV/1234567/consumer` */
  client?: string;
  /** e.g. `SERVICE:EXAMPLE/GOV/7654321/producer/getRandom/v1` */
  service?: string;
  /** SOAP xroad:id / REST X-Road-Id */
  queryId?: string;
  userId?: string;
  issue?: string;
  /** SOAP only */
  protocolVersion?: string;
  /** e.g. `SERVER:EXAMPLE/GOV/1234567/ss1` */
  securityServer?: string;
  /** `class/code` or `code` */
  representedParty?: string;
  requestHash?: string;
  requestHashAlgorithm?: string;
  /** SOAP: local name of the Body's first element */
  serviceName?: string;
  /** REST request */
  verb?: string;
  path?: string;
  query?: string;
  /** REST response */
  status?: string;
  reason?: string;
  /** REST: X-Road-Request-Id */
  requestId?: string;
  /** REST: every header line in order, value untrimmed */
  restHeaders?: { name: string; value: string }[];
}

export interface SignerError {
  faultCode: string;
  faultString: string;
  /** true: Java getSigner throws (fail at V3); false: Java returns null (fail at S3). */
  thrown: boolean;
  /** The underlying parser error (code + message), for diagnostics. */
  cause?: { faultCode: string; faultString: string };
}

export interface ParsedMessage {
  /** 'soap' if it parsed as a SOAP envelope; 'rest' if the REST fallback ran (success or not). */
  kind: 'soap' | 'rest';
  /** null when undeterminable (SOAP without a Body element, REST that does not parse). */
  direction: 'request' | 'response' | null;
  header: MessageHeaderView;
  expectedSigner: ClientId | null;
  /** clientIdToString(expectedSigner) */
  expectedSignerId: string | null;
  signerError?: SignerError;
}

export const INVALID_MESSAGE = 'Invalid message';
/** faultString used for a null signer (Java: NPE "... because \"signer\" is null"). */
export const NULL_SIGNER_MESSAGE = 'Cannot derive the signer from the message (signer is null)';

function causeOf(e: unknown): { faultCode: string; faultString: string } {
  if (e instanceof CodedError) return { faultCode: e.faultCode, faultString: e.faultString };
  return { faultCode: ErrorCodes.X_INTERNAL_ERROR, faultString: e instanceof Error ? e.message : String(e) };
}

function soapView(r: SoapParseResult): MessageHeaderView {
  const h = r.header;
  const v: MessageHeaderView = {};
  if (h.client) v.client = clientIdToString(h.client);
  if (h.service) v.service = serviceIdToString(h.service);
  if (h.queryId != null) v.queryId = h.queryId;
  if (h.userId != null) v.userId = h.userId;
  if (h.issue != null) v.issue = h.issue;
  if (h.protocolVersion != null) v.protocolVersion = h.protocolVersion;
  if (h.securityServer) v.securityServer = securityServerIdToString(h.securityServer);
  if (h.representedParty) v.representedParty = partyString(h.representedParty);
  if (h.requestHash) {
    v.requestHash = h.requestHash.value;
    if (h.requestHash.algorithmId != null) v.requestHashAlgorithm = h.requestHash.algorithmId;
  }
  if (r.serviceName != null) v.serviceName = r.serviceName;
  return v;
}

function partyString(p: { partyClass: string | null; partyCode: string | null }): string {
  return [p.partyClass, p.partyCode].filter((x) => x != null).join('/');
}

function restView(r: RestParseResult): MessageHeaderView {
  const v: MessageHeaderView = {
    service: serviceIdToString(r.service),
    restHeaders: r.headers.map(([name, value]) => ({ name, value })),
  };
  if (r.client) v.client = clientIdToString(r.client);
  if (r.queryId != null) v.queryId = r.queryId;
  if (r.userId != null) v.userId = r.userId;
  if (r.issue != null) v.issue = r.issue;
  if (r.requestId != null) v.requestId = r.requestId;
  if (r.direction === 'request') {
    v.verb = r.verb;
    v.path = r.path;
    if (r.query != null) v.query = r.query;
    if (r.securityServer) v.securityServer = securityServerIdToString(r.securityServer);
    if (r.representedParty) v.representedParty = partyString(r.representedParty);
  } else {
    v.status = String(r.status);
    if (r.reason != null) v.reason = r.reason;
    v.requestHash = r.requestHash;
  }
  return v;
}

function withSigner(base: Omit<ParsedMessage, 'expectedSigner' | 'expectedSignerId'>, signer: ClientId | null): ParsedMessage {
  return { ...base, expectedSigner: signer, expectedSignerId: signer ? clientIdToString(signer) : null };
}

function parseRestFallback(text: string): ParsedMessage {
  let r: RestParseResult;
  try {
    r = parseRest(text);
  } catch (e) {
    return withSigner(
      {
        kind: 'rest',
        direction: null,
        header: {},
        signerError: { faultCode: ErrorCodes.X_INTERNAL_ERROR, faultString: INVALID_MESSAGE, thrown: true, cause: causeOf(e) },
      },
      null,
    );
  }
  const base = { kind: 'rest' as const, direction: r.direction, header: restView(r) };
  if (r.sender == null) {
    return withSigner(
      {
        ...base,
        signerError: {
          faultCode: ErrorCodes.X_INTERNAL_ERROR,
          faultString: NULL_SIGNER_MESSAGE,
          thrown: false,
          cause: { faultCode: ErrorCodes.X_INTERNAL_ERROR, faultString: 'X-Road-Client header missing' },
        },
      },
      null,
    );
  }
  return withSigner(base, r.sender);
}

/** Parse message.xml text (the container's lenient UTF-8 string) or a container's message. */
export function parseMessage(input: AsicContainer | string): ParsedMessage {
  const text = typeof input === 'string' ? input : (input.get(ENTRY_MESSAGE) ?? '');

  let soap: SoapParseResult;
  try {
    soap = parseSoap(text);
  } catch (e) {
    if (e instanceof CodedError && e.faultCode === ErrorCodes.X_INVALID_SOAP) return parseRestFallback(text);
    // Not expected: parseSoap returns every other error.
    return withSigner(
      {
        kind: 'soap',
        direction: null,
        header: {},
        signerError: { faultCode: ErrorCodes.X_INTERNAL_ERROR, faultString: NULL_SIGNER_MESSAGE, thrown: false, cause: causeOf(e) },
      },
      null,
    );
  }

  const direction: ParsedMessage['direction'] = soap.serviceName == null ? null : isResponseServiceName(soap.serviceName) ? 'response' : 'request';
  const base = { kind: 'soap' as const, direction, header: soapView(soap) };
  if (soap.error) {
    return withSigner(
      {
        ...base,
        signerError: {
          faultCode: ErrorCodes.X_INTERNAL_ERROR,
          faultString: NULL_SIGNER_MESSAGE,
          thrown: false,
          cause: causeOf(soap.error),
        },
      },
      null,
    );
  }
  // A valid SoapMessageImpl: header client/service and serviceName are present.
  if (direction === 'request') return withSigner(base, soap.header.client!);
  try {
    return withSigner(base, serviceClientId(soap.header.service!));
  } catch (e) {
    // service.getClientId() rejects a blank subsystemCode: an IllegalArgumentException
    // that getSigner does not catch → verify() fails with internal_error at V3.
    if (!(e instanceof IdentifierError)) throw e;
    return withSigner(
      { ...base, signerError: { faultCode: ErrorCodes.X_INTERNAL_ERROR, faultString: e.message, thrown: true, cause: causeOf(e) } },
      null,
    );
  }
}
