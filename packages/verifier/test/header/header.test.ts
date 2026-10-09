import { describe, expect, it } from 'vitest';
import { clientIdToString, parseMessage, serviceIdToString } from '../../src/header/index';
import { createClientId, createServiceId } from '../../src/header/ids';
import {
  javaReadLines,
  javaSplit,
  parseRequestUri,
  parseRest,
  uriSegmentPercentDecode,
} from '../../src/header/rest';
import { parseSoap } from '../../src/header/soap';

// ---------- SOAP builders ----------

const client = (sub: string | null = 'consumer', type = sub == null ? 'MEMBER' : 'SUBSYSTEM') =>
  `<xrd:client id:objectType="${type}"><id:xRoadInstance>EXAMPLE</id:xRoadInstance><id:memberClass>gov</id:memberClass>` +
  `<id:memberCode>00000002</id:memberCode>${sub == null ? '' : `<id:subsystemCode>${sub}</id:subsystemCode>`}</xrd:client>`;

const service = (code = 'getTodo', sub: string | null = 'todos') =>
  `<xrd:service id:objectType="SERVICE"><id:xRoadInstance>EXAMPLE</id:xRoadInstance><id:memberClass>gov</id:memberClass>` +
  `<id:memberCode>00000003</id:memberCode>${sub == null ? '' : `<id:subsystemCode>${sub}</id:subsystemCode>`}` +
  `<id:serviceCode>${code}</id:serviceCode><id:serviceVersion>v1</id:serviceVersion></xrd:service>`;

const STD_HEADER = `${client()}${service()}<xrd:id>q-1</xrd:id><xrd:userId>EE1</xrd:userId><xrd:protocolVersion>4.0</xrd:protocolVersion>`;

const env = (header: string | null, body: string | null) =>
  `<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" ` +
  `xmlns:xrd="http://x-road.eu/xsd/xroad.xsd" xmlns:id="http://x-road.eu/xsd/identifiers" ` +
  `xmlns:repr="http://x-road.eu/xsd/representation.xsd">` +
  (header == null ? '' : `<SOAP-ENV:Header>${header}</SOAP-ENV:Header>`) +
  (body == null ? '' : `<SOAP-ENV:Body>${body}</SOAP-ENV:Body>`) +
  `</SOAP-ENV:Envelope>`;

const soapCause = (xml: string) => {
  const p = parseMessage(xml);
  expect(p.kind).toBe('soap');
  expect(p.expectedSigner).toBeNull();
  expect(p.signerError?.thrown).toBe(false);
  expect(p.signerError?.faultCode).toBe('internal_error');
  return p.signerError!.cause!.faultCode;
};

describe('identifiers', () => {
  it('ClientId.toString: type from subsystem nullity, nulls skipped, no escaping', () => {
    expect(clientIdToString(createClientId('EXAMPLE', 'gov', 'a/b', null))).toBe('MEMBER:EXAMPLE/gov/a/b');
    expect(clientIdToString(createClientId('I', 'C', 'M', 'S'))).toBe('SUBSYSTEM:I/C/M/S');
    expect(serviceIdToString(createServiceId('I', 'C', 'M', null, 'svc', null))).toBe('SERVICE:I/C/M/svc');
    expect(serviceIdToString(createServiceId('I', 'C', 'M', 'S', 'svc', 'v1'))).toBe('SERVICE:I/C/M/S/svc/v1');
  });
  it('blank required parts are rejected (Java isBlank), values are not trimmed', () => {
    expect(() => createClientId(' ', 'C', 'M', null)).toThrow();
    expect(() => createClientId('I', 'C', 'M', '')).toThrow();
    expect(createClientId(' I', 'C', 'M', null).xRoadInstance).toBe(' I');
    // ServiceId.Conf.create does not validate the subsystem
    expect(createServiceId('I', 'C', 'M', '', 's', null).subsystemCode).toBe('');
  });
});

describe('SOAP', () => {
  it('request: signer = client; display fields', () => {
    const p = parseMessage(env(STD_HEADER, '<xrd:getTodo><x>1</x></xrd:getTodo>'));
    expect(p).toMatchObject({ kind: 'soap', direction: 'request', expectedSignerId: 'SUBSYSTEM:EXAMPLE/gov/00000002/consumer' });
    expect(p.signerError).toBeUndefined();
    expect(p.header).toEqual({
      client: 'SUBSYSTEM:EXAMPLE/gov/00000002/consumer',
      service: 'SERVICE:EXAMPLE/gov/00000003/todos/getTodo/v1',
      queryId: 'q-1',
      userId: 'EE1',
      protocolVersion: '4.0',
      serviceName: 'getTodo',
    });
  });

  it('response: signer = service.getClientId() (keeps the subsystem)', () => {
    const hash = '<xrd:requestHash algorithmId="http://www.w3.org/2001/04/xmlenc#sha512">AAAA</xrd:requestHash>';
    const p = parseMessage(env(STD_HEADER + hash, '<xrd:getTodoResponse/>'));
    expect(p.direction).toBe('response');
    expect(p.expectedSignerId).toBe('SUBSYSTEM:EXAMPLE/gov/00000003/todos');
    expect(p.header.requestHash).toBe('AAAA');
    expect(p.header.requestHashAlgorithm).toBe('http://www.w3.org/2001/04/xmlenc#sha512');
  });

  it('response of a member-owned service → MEMBER signer', () => {
    const h = `${client()}${service('getTodo', null)}<xrd:id>q</xrd:id><xrd:protocolVersion>4.0</xrd:protocolVersion>`;
    expect(parseMessage(env(h, '<getTodoResponse/>')).expectedSignerId).toBe('MEMBER:EXAMPLE/gov/00000003');
  });

  it('member client, objectType does not decide the type', () => {
    const h = `${client(null)}${service()}<xrd:id>q</xrd:id><xrd:protocolVersion>4.0</xrd:protocolVersion>`;
    expect(parseMessage(env(h, '<getTodo/>')).expectedSignerId).toBe('MEMBER:EXAMPLE/gov/00000002');
    const h2 = `${client('sub', 'MEMBER')}${service()}<xrd:id>q</xrd:id><xrd:protocolVersion>4.0</xrd:protocolVersion>`;
    expect(parseMessage(env(h2, '<getTodo/>')).expectedSignerId).toBe('SUBSYSTEM:EXAMPLE/gov/00000002/sub');
  });

  it('"Response" suffix is case-sensitive; response decided by the first body child', () => {
    expect(parseMessage(env(STD_HEADER, '<getTodoresponse/>')).direction).toBe('request');
  });

  it('BOM, comments and whitespace are tolerated; values are not trimmed', () => {
    const h = STD_HEADER.replace('<xrd:id>q-1</xrd:id>', '<xrd:id> q<!-- c -->1 </xrd:id>');
    const p = parseMessage('﻿' + env(h, '\n  <getTodo/>\n'));
    expect(p.signerError).toBeUndefined();
    expect(p.header.queryId).toBe(' q1 ');
  });

  it('represented party and security server', () => {
    const extra =
      '<repr:representedParty><repr:partyClass>COM</repr:partyClass><repr:partyCode>123</repr:partyCode></repr:representedParty>' +
      '<xrd:securityServer id:objectType="SERVER"><id:xRoadInstance>I</id:xRoadInstance><id:memberClass>C</id:memberClass>' +
      '<id:memberCode>M</id:memberCode><id:serverCode>ss1</id:serverCode></xrd:securityServer>';
    const p = parseMessage(env(STD_HEADER + extra, '<getTodo/>'));
    expect(p.header.representedParty).toBe('COM/123');
    expect(p.header.securityServer).toBe('SERVER:I/C/M/ss1');
  });

  describe('swallowed errors → signer null (internal_error at S3)', () => {
    it.each([
      ['missing header', env(null, '<getTodo/>'), 'missing_header'],
      ['missing protocolVersion', env(STD_HEADER.replace(/<xrd:protocolVersion>.*<\/xrd:protocolVersion>/, ''), '<getTodo/>'), 'missing_header_field'],
      ['missing client', env(STD_HEADER.replace(client(), ''), '<getTodo/>'), 'missing_header_field'],
      ['missing id', env(STD_HEADER.replace('<xrd:id>q-1</xrd:id>', ''), '<getTodo/>'), 'missing_header_field'],
      ['missing service', env(STD_HEADER.replace(service(), ''), '<getTodo/>'), 'missing_header_field'],
      ['duplicate id', env(STD_HEADER + '<xrd:id>q-2</xrd:id>', '<getTodo/>'), 'duplicate_header_field'],
      ['duplicate client part', env(STD_HEADER.replace('</id:memberCode>', '</id:memberCode><id:memberCode>x</id:memberCode>'), '<getTodo/>'), 'duplicate_header_field'],
      ['protocol version not 4.x', env(STD_HEADER.replace('>4.0<', '>5.0<'), '<getTodo/>'), 'invalid_protocol_version'],
      ['missing objectType', env(STD_HEADER.replace('xrd:client id:objectType="SUBSYSTEM"', 'xrd:client'), '<getTodo/>'), 'invalid_xml'],
      ['unexpected objectType', env(STD_HEADER.replace('objectType="SUBSYSTEM"', 'objectType="SERVICE"'), '<getTodo/>'), 'invalid_xml'],
      ['unknown objectType', env(STD_HEADER.replace('objectType="SUBSYSTEM"', 'objectType="FOO"'), '<getTodo/>'), 'invalid_xml'],
      ['blank member code', env(STD_HEADER.replace('>00000002<', '> <'), '<getTodo/>'), 'internal_error'],
      ['empty subsystem code', env(STD_HEADER.replace('>consumer<', '><'), '<getTodo/>'), 'internal_error'],
      ['missing body', env(STD_HEADER, null), 'missing_body'],
      ['empty body', env(STD_HEADER, ''), 'invalid_body'],
      ['two body children', env(STD_HEADER, '<getTodo/><other/>'), 'invalid_body'],
      ['service code mismatch', env(STD_HEADER, '<somethingElse/>'), 'inconsistent_headers'],
      ['SOAP fault', env(STD_HEADER, '<SOAP-ENV:Fault><faultcode>x</faultcode></SOAP-ENV:Fault>'), 'internal_error'],
    ])('%s', (_n, xml, cause) => {
      expect(soapCause(xml)).toBe(cause);
    });

    it('a fault skips header validation', () => {
      const p = parseMessage(env(null, '<SOAP-ENV:Fault/>'));
      expect(p.signerError?.cause?.faultString).toMatch(/Unexpected SOAP/);
    });

    it('errors keep the fields parsed so far for display', () => {
      const p = parseMessage(env(STD_HEADER, '<somethingElse/>'));
      expect(p.header.client).toBe('SUBSYSTEM:EXAMPLE/gov/00000002/consumer');
      expect(p.direction).toBe('request');
    });
  });

  it('response whose service has a blank subsystem → thrown internal_error (uncaught IAE)', () => {
    const h = STD_HEADER.replace('>todos<', '> <');
    const p = parseMessage(env(h, '<getTodoResponse/>'));
    expect(p.expectedSigner).toBeNull();
    expect(p.signerError).toMatchObject({ faultCode: 'internal_error', thrown: true });
    // ...but as a request the service's subsystem is never validated
    expect(parseMessage(env(h, '<getTodo/>')).signerError).toBeUndefined();
  });

  it('invalid_soap only for not-well-formed / DOCTYPE / non-Envelope root', () => {
    expect(() => parseSoap('<a>')).toThrow(/invalid_soap/);
    expect(() => parseSoap('<!DOCTYPE a><a/>')).toThrow(/invalid_soap/);
    expect(() => parseSoap('<a/>')).toThrow(/envelope missing/);
    expect(() => parseSoap('<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"/>')).toThrow(/invalid_soap/);
    expect(parseSoap(env(null, null)).error?.faultCode).toBe('missing_header');
  });

  it('non-SOAP XML falls back to REST and fails as "Invalid message" (thrown)', () => {
    for (const xml of ['<a/>', '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">', '   ']) {
      const p = parseMessage(xml);
      expect(p.kind).toBe('rest');
      expect(p.signerError).toMatchObject({ faultCode: 'internal_error', faultString: 'Invalid message', thrown: true });
    }
  });
});

// ---------- REST ----------

const REQ =
  'GET\r\n/r1/EXAMPLE/gov/00000003/petstore/petstore/store/inventory?a=1\r\nAccept:*/*\r\n' +
  'X-Road-Client:EXAMPLE/gov/00000002/client\r\nx-road-request-id:rid\r\nx-road-id:qid\r\nX-Road-UserId:u1\r\n';

const RESP =
  '200\r\nOK\r\nContent-Type:application/json\r\nx-road-id:qid\r\nx-road-client:EXAMPLE/gov/00000002/client\r\n' +
  'x-road-service:EXAMPLE/gov/00000003/petstore/petstore\r\nx-road-request-hash:AAAA\r\n';

const restThrown = (msg: string) => {
  const p = parseMessage(msg);
  expect(p.kind).toBe('rest');
  expect(p.expectedSigner).toBeNull();
  expect(p.signerError).toMatchObject({ faultCode: 'internal_error', faultString: 'Invalid message', thrown: true });
  return p.signerError!.cause!.faultString;
};

describe('REST', () => {
  it('request: signer = X-Road-Client; display fields', () => {
    const p = parseMessage(REQ);
    expect(p).toMatchObject({ kind: 'rest', direction: 'request', expectedSignerId: 'SUBSYSTEM:EXAMPLE/gov/00000002/client' });
    expect(p.header).toMatchObject({
      verb: 'GET',
      path: '/r1/EXAMPLE/gov/00000003/petstore/petstore/store/inventory',
      query: 'a=1',
      service: 'SERVICE:EXAMPLE/gov/00000003/petstore/petstore',
      client: 'SUBSYSTEM:EXAMPLE/gov/00000002/client',
      queryId: 'qid',
      requestId: 'rid',
      userId: 'u1',
    });
    expect(p.header.restHeaders?.[0]).toEqual({ name: 'Accept', value: '*/*' });
  });

  it('response: signer = client part of x-road-service', () => {
    const p = parseMessage(RESP);
    expect(p).toMatchObject({ kind: 'rest', direction: 'response', expectedSignerId: 'SUBSYSTEM:EXAMPLE/gov/00000003/petstore' });
    expect(p.header).toMatchObject({ status: '200', reason: 'OK', requestHash: 'AAAA', queryId: 'qid' });
  });

  it('response with an empty reason line (as security servers write it)', () => {
    expect(parseMessage(RESP.replace('OK', '')).expectedSignerId).toBe('SUBSYSTEM:EXAMPLE/gov/00000003/petstore');
  });

  it('member client, percent-decoding, last X-Road-Client wins, \\n line endings', () => {
    const msg = 'POST\n/r1/I/C/M/S/svc\nx-road-client:I/C/a%2Fb\nX-ROAD-CLIENT:I/C/M%C3%A4\n';
    expect(parseMessage(msg).expectedSignerId).toBe('MEMBER:I/C/Mä');
  });

  it('request without X-Road-Client → signer null, not thrown', () => {
    const p = parseMessage(REQ.replace('X-Road-Client:EXAMPLE/gov/00000002/client\r\n', ''));
    expect(p.direction).toBe('request');
    expect(p.signerError).toMatchObject({ faultCode: 'internal_error', thrown: false });
  });

  it.each([
    ['unknown verb', REQ.replace('GET', 'get')],
    ['verb only', 'GET'],
    ['absolute URI', REQ.replace('/r1/', 'http://h/r1/')],
    ['authority', REQ.replace('/r1/', '//h/r1/')],
    ['space in URI', REQ.replace('store/inventory', 'store inventory')],
    ['bad escape in URI', REQ.replace('inventory', 'inv%zz')],
    ['too few path parts', 'GET\n/r1/I/C/M/S\n'],
    ['wrong protocol version', REQ.replace('/r1/', '/r2/')],
    ['bad protocol version', REQ.replace('/r1/', '/rx/')],
    ['blank service code in path', 'GET\n/r1/I/C/M/S/%20\n'],
    ['empty line after headers', REQ + '\r\n'],
    ['header without colon', REQ + 'garbage\r\n'],
    ['hop-by-hop header', REQ + 'Host:x\r\n'],
    ['leading space in X-Road-Client', REQ.replace('X-Road-Client:', 'X-Road-Client: ')],
    ['client with 2 parts', REQ.replace('EXAMPLE/gov/00000002/client', 'EXAMPLE/gov')],
    ['client with 5 parts', REQ.replace('EXAMPLE/gov/00000002/client', 'a/b/c/d/e')],
    ['client trailing slash (empty subsystem)', REQ.replace('EXAMPLE/gov/00000002/client', 'a/b/c/')],
    ['bad security server', REQ + 'X-Road-Security-Server:a/b/c\r\n'],
    ['bad represented party', REQ + 'X-Road-Represented-Party:a/b/c\r\n'],
    ['response: status not an int', RESP.replace('200', '200 OK')],
    ['response: status overflow', RESP.replace('200', '99999999999')],
    ['response: missing x-road-id', RESP.replace('x-road-id:qid\r\n', '')],
    ['response: empty x-road-id', RESP.replace('x-road-id:qid', 'x-road-id:')],
    ['response: missing request hash', RESP.replace('x-road-request-hash:AAAA\r\n', '')],
    ['response: request hash decodes to nothing', RESP.replace('x-road-request-hash:AAAA', 'x-road-request-hash:!!')],
    ['response: missing x-road-service', RESP.replace('x-road-service:EXAMPLE/gov/00000003/petstore/petstore\r\n', '')],
    ['response: service with 4 parts', RESP.replace('00000003/petstore/petstore', '00000003/petstore')],
    ['response: service with empty subsystem', RESP.replace('00000003/petstore/petstore', '00000003//petstore')],
    ['response: bad x-road-client', RESP.replace('x-road-client:EXAMPLE/gov/00000002/client', 'x-road-client:a')],
  ])('%s → thrown "Invalid message"', (_n, msg) => {
    expect(restThrown(msg)).toBeTruthy();
  });

  it('first byte 1..9 → response, otherwise request', () => {
    expect(parseRest(RESP).direction).toBe('response');
    expect(() => parseRest('0\n')).toThrow(/Verb/);
  });
});

describe('REST helpers', () => {
  it('javaReadLines', () => {
    expect(javaReadLines('a\r\nb\rc\nd')).toEqual(['a', 'b', 'c', 'd']);
    expect(javaReadLines('a\n')).toEqual(['a']);
    expect(javaReadLines('a\n\n')).toEqual(['a', '']);
    expect(javaReadLines('200\r\n\r\n')).toEqual(['200', '']);
  });
  it('javaSplit keeps trailing empties with a limit and drops them without', () => {
    expect(javaSplit('a/b/c/', '/', 5)).toEqual(['a', 'b', 'c', '']);
    expect(javaSplit('a/b/c/d/e/f', '/', 5)).toEqual(['a', 'b', 'c', 'd', 'e/f']);
    expect(javaSplit('a/b//', '/')).toEqual(['a', 'b']);
    expect(javaSplit('/', '/')).toEqual([]);
    expect(javaSplit('', '/')).toEqual(['']);
    expect(javaSplit('/r1/a', '/', 8)).toEqual(['', 'r1', 'a']);
  });
  it('uriSegmentPercentDecode', () => {
    expect(uriSegmentPercentDecode("a-._~!$&'()*+,;=:@")).toBe("a-._~!$&'()*+,;=:@");
    expect(uriSegmentPercentDecode('a%2Fb%20')).toBe('a/b ');
    for (const bad of ['a b', 'a/b', 'ä', '%2', '%zz', 'a%']) expect(() => uriSegmentPercentDecode(bad)).toThrow();
  });
  it('parseRequestUri', () => {
    expect(parseRequestUri('/a/b?x=[1]#f')).toEqual({ rawPath: '/a/b', rawQuery: 'x=[1]' });
    expect(parseRequestUri('///a')).toEqual({ rawPath: '/a', rawQuery: null });
    expect(parseRequestUri('/ä')).toEqual({ rawPath: '/ä', rawQuery: null });
    for (const bad of ['a:b', 'http://x/', '//h/a', '/a b', '/a[', '/%', '/a?b c']) expect(() => parseRequestUri(bad)).toThrow();
  });
});
