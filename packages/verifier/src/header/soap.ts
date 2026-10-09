/**
 * SOAP message header parsing: a DOM port of SaxSoapParserImpl (7.8.3) as used
 * by AsicContainerVerifier.getSigner (header/README.md).
 *
 *   parseSoap(text) → SoapParseResult
 *     - throws CodedError('invalid_soap') ONLY for not-well-formed XML, a DOCTYPE,
 *       or a root that is not {soap-1.1}Envelope; the caller then tries REST
 *     - every other problem is returned as `error` (Java: a CodedException that
 *       getSigner swallows → signer null), together with whatever header fields
 *       were parsed before it (for display)
 *
 * Elements are visited depth-first in document order, so the first error is the
 * one the SAX parser would raise (except: SAX raises a handler error before a
 * well-formedness error later in the document; we report invalid_soap).
 */
import { CodedError, ErrorCodes } from '../util/errors';
import { childElements, directText, parseXml, type XElement } from '../xml/safe';
import {
  createClientId,
  createSecurityServerId,
  createServiceId,
  IdentifierError,
  type ClientId,
  type SecurityServerId,
  type ServiceId,
} from './ids';

export const NS_SOAPENV = 'http://schemas.xmlsoap.org/soap/envelope/';
export const NS_XROAD = 'http://x-road.eu/xsd/xroad.xsd';
export const NS_IDENTIFIERS = 'http://x-road.eu/xsd/identifiers';
export const NS_REPR = 'http://x-road.eu/xsd/representation.xsd';

export interface SoapHeaderFields {
  queryId?: string;
  userId?: string;
  issue?: string;
  protocolVersion?: string;
  client?: ClientId;
  service?: ServiceId;
  securityServer?: SecurityServerId;
  representedParty?: { partyClass: string | null; partyCode: string | null };
  requestHash?: { algorithmId: string | null; value: string };
}

export interface SoapParseResult {
  header: SoapHeaderFields;
  /** Local name of the first non-Fault Body child (Java serviceName). */
  serviceName?: string;
  /** True if the Body contains a soap:Fault (Java returns a SoapFault). */
  fault: boolean;
  /** Set iff the parse failed in a way getSigner swallows (or the message is a Fault). */
  error?: CodedError;
}

const ID_CLIENT = ['xRoadInstance', 'memberClass', 'memberCode', 'subsystemCode'];
const ID_SERVICE = [...ID_CLIENT, 'serviceCode', 'serviceVersion'];
const ID_SERVER = ['xRoadInstance', 'memberClass', 'memberCode', 'serverCode'];

const is = (el: XElement, ns: string, local: string) => el.namespaceURI === ns && el.localName === local;

const qn = (ns: string, local: string) => `{${ns}}${local}`;

function duplicate(ns: string, local: string): CodedError {
  return new CodedError(ErrorCodes.X_DUPLICATE_HEADER_FIELD, `Malformed SOAP message: duplicate header field ${qn(ns, local)}`);
}

/** XRoadIdentifierHeaderHandler: objectType check (openTag) and the allowed id:* children. */
function readIdentifier(el: XElement, expected: readonly string[], allowed: readonly string[]): Map<string, string> {
  const objectType = el.getAttributeNS(NS_IDENTIFIERS, 'objectType');
  if (objectType == null || !el.hasAttributeNS(NS_IDENTIFIERS, 'objectType')) {
    throw new CodedError(ErrorCodes.X_INVALID_XML, 'Missing objectType attribute');
  }
  if (!expected.includes(objectType)) {
    throw new CodedError(ErrorCodes.X_INVALID_XML, `Unexpected objectType: ${objectType}`);
  }
  const values = new Map<string, string>();
  for (const c of childElements(el)) {
    const name = c.localName ?? '';
    if (c.namespaceURI !== NS_IDENTIFIERS || !allowed.includes(name)) continue;
    if (values.has(name)) throw duplicate(NS_IDENTIFIERS, name);
    values.set(name, directText(c));
  }
  return values;
}

function readHeader(headerEl: XElement, h: SoapHeaderFields): void {
  for (const el of childElements(headerEl)) {
    if (el.namespaceURI === NS_XROAD) {
      switch (el.localName) {
        case 'id':
          if (h.queryId != null) throw duplicate(NS_XROAD, 'id');
          h.queryId = directText(el);
          break;
        case 'userId':
          if (h.userId != null) throw duplicate(NS_XROAD, 'userId');
          h.userId = directText(el);
          break;
        case 'issue':
          if (h.issue != null) throw duplicate(NS_XROAD, 'issue');
          h.issue = directText(el);
          break;
        case 'protocolVersion': {
          if (h.protocolVersion != null) throw duplicate(NS_XROAD, 'protocolVersion');
          const v = directText(el);
          if (!v.startsWith('4.')) {
            throw new CodedError(
              ErrorCodes.X_INVALID_PROTOCOL_VERSION,
              `Invalid protocol version (supported: 4.x, provided: ${v})`,
            );
          }
          h.protocolVersion = v;
          break;
        }
        case 'client': {
          if (h.client != null) throw duplicate(NS_XROAD, 'client');
          const v = readIdentifier(el, ['MEMBER', 'SUBSYSTEM'], ID_CLIENT);
          h.client = createClientId(v.get('xRoadInstance'), v.get('memberClass'), v.get('memberCode'), v.get('subsystemCode'));
          break;
        }
        case 'service': {
          if (h.service != null) throw duplicate(NS_XROAD, 'service');
          const v = readIdentifier(el, ['SERVICE'], ID_SERVICE);
          h.service = createServiceId(
            v.get('xRoadInstance'),
            v.get('memberClass'),
            v.get('memberCode'),
            v.get('subsystemCode'),
            v.get('serviceCode'),
            v.get('serviceVersion'),
          );
          break;
        }
        case 'securityServer': {
          if (h.securityServer != null) throw duplicate(NS_XROAD, 'securityServer');
          const v = readIdentifier(el, ['SERVER'], ID_SERVER);
          h.securityServer = createSecurityServerId(v.get('xRoadInstance'), v.get('memberClass'), v.get('memberCode'), v.get('serverCode'));
          break;
        }
        case 'requestHash':
          if (h.requestHash != null) throw duplicate(NS_XROAD, 'requestHash');
          h.requestHash = {
            algorithmId: el.hasAttributeNS(null, 'algorithmId') ? el.getAttributeNS(null, 'algorithmId') : null,
            value: directText(el),
          };
          break;
      }
    } else if (is(el, NS_REPR, 'representedParty')) {
      if (h.representedParty != null) throw duplicate(NS_REPR, 'representedParty');
      const values = new Map<string, string>();
      for (const c of childElements(el)) {
        const name = c.localName ?? '';
        if (c.namespaceURI !== NS_REPR || (name !== 'partyClass' && name !== 'partyCode')) continue;
        if (values.has(name)) throw duplicate(NS_REPR, name);
        values.set(name, directText(c));
      }
      h.representedParty = { partyClass: values.get('partyClass') ?? null, partyCode: values.get('partyCode') ?? null };
    }
  }
}

interface BodyState {
  serviceName?: string;
  fault: boolean;
}

/** SoapBodyHandler.getChildElementHandler. */
function readBody(bodyEl: XElement): BodyState {
  const b: BodyState = { fault: false };
  for (const el of childElements(bodyEl)) {
    if (is(el, NS_SOAPENV, 'Fault')) b.fault = true;
    else if (b.serviceName == null) b.serviceName = el.localName ?? '';
    else throw new CodedError(ErrorCodes.X_INVALID_BODY, 'Malformed SOAP message: body must have exactly one child element');
  }
  return b;
}

/** SoapEnvelopeHandler.closeTag (only when there is no Fault). */
function validateEnvelope(headerSeen: boolean, h: SoapHeaderFields, body: BodyState | undefined): void {
  if (!headerSeen) throw new CodedError(ErrorCodes.X_MISSING_HEADER, 'Malformed SOAP message: header missing');
  const missing = (f: string) => new CodedError(ErrorCodes.X_MISSING_HEADER_FIELD, `Required field '${f}' is missing`);
  if (h.protocolVersion == null) throw missing('protocolVersion');
  if (h.client == null) throw missing('client');
  if (h.queryId == null) throw missing('id');
  if (h.service == null) throw new CodedError(ErrorCodes.X_MISSING_HEADER_FIELD, 'Malformed SOAP message: service missing');
  if (body == null) throw new CodedError(ErrorCodes.X_MISSING_BODY, 'Malformed SOAP message: body missing');
  if (body.serviceName == null) throw new CodedError(ErrorCodes.X_INVALID_BODY, 'Malformed SOAP message: body must have exactly one child element');
  if (!body.serviceName.startsWith(h.service.serviceCode)) {
    throw new CodedError(
      ErrorCodes.X_INCONSISTENT_HEADERS,
      'Malformed SOAP message: service code does not match in header and body',
    );
  }
}

export function parseSoap(text: string): SoapParseResult {
  // excludeUtf8Bom: a leading BOM is skipped.
  const doc = parseXml(text.startsWith('﻿') ? text.slice(1) : text, ErrorCodes.X_INVALID_SOAP);
  const root = doc.documentElement!;
  if (!is(root, NS_SOAPENV, 'Envelope')) {
    throw new CodedError(ErrorCodes.X_INVALID_SOAP, 'Malformed SOAP message: envelope missing');
  }

  const header: SoapHeaderFields = {};
  let headerSeen = false;
  let body: BodyState | undefined;
  const result = (error?: CodedError): SoapParseResult => ({
    header,
    serviceName: body?.serviceName,
    fault: body?.fault ?? false,
    ...(error ? { error } : {}),
  });

  try {
    for (const el of childElements(root)) {
      if (is(el, NS_SOAPENV, 'Header')) {
        readHeader(el, header);
        headerSeen = true;
      } else if (is(el, NS_SOAPENV, 'Body')) {
        body = readBody(el); // a later Body replaces an earlier one (new SoapBodyHandler)
      }
    }
    if (body?.fault) {
      return result(new CodedError(ErrorCodes.X_INTERNAL_ERROR, 'Unexpected SOAP: SOAP Fault message'));
    }
    validateEnvelope(headerSeen, header, body);
  } catch (e) {
    if (e instanceof CodedError) return result(e);
    // Identifier validation (Java IllegalArgumentException → translateException → internal_error).
    if (e instanceof IdentifierError) return result(new CodedError(ErrorCodes.X_INTERNAL_ERROR, e.message, { cause: e }));
    throw e;
  }
  return result();
}

/** SoapUtils.isResponseMessage: the service name ends with "Response". */
export function isResponseServiceName(serviceName: string): boolean {
  return serviceName.endsWith('Response');
}
