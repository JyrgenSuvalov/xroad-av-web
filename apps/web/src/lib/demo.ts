// DEV-ONLY demo fixtures: `?demo=ok|ok-rest|unverified|fail` and
// `?trust=fresh|stale|failed|none`. App.svelte imports this module only behind
// `import.meta.env.DEV`, so it is not in the production build (a URL that
// shows a green verdict for a file nobody dropped must not exist there).
//
// The values are made up, in the shape the verifier returns.

import type { CertSummary, VerificationResult } from '@xrav/verifier';
import type { MessageView, MessageViewResult } from './messageView';
import type { TrustView } from './trust.svelte';

export type DemoKind = 'ok' | 'ok-rest' | 'unverified' | 'fail';

export interface DemoCase {
  fileName: string;
  size: number;
  result: VerificationResult;
  message: MessageViewResult;
}

const CONF_VERSION = 'V6/20260115100000000000000';
const CA = 'CN=Example CA,O=Example';

const cert = (subject: string, serial: string, from: string, until: string): CertSummary => ({
  subject,
  issuer: CA,
  serialNumber: serial,
  notBefore: from,
  notAfter: until,
});

const OCSP = {
  signedBy: cert('CN=Example OCSP,O=Example', '1', '2026-01-01T00:00:00.000Z', '2036-01-01T00:00:00.000Z'),
};
const TSA = cert('CN=Example TSA,O=Example', '2', '2026-01-01T00:00:00.000Z', '2036-01-01T00:00:00.000Z');

const enc = new TextEncoder();

const SOAP_XML =
  '<?xml version="1.0" encoding="utf-8" ?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:id="http://x-road.eu/xsd/identifiers" xmlns:xroad="http://x-road.eu/xsd/xroad.xsd"><SOAP-ENV:Header><xroad:client id:objectType="SUBSYSTEM"><id:xRoadInstance>EXAMPLE</id:xRoadInstance><id:memberClass>GOV</id:memberClass><id:memberCode>1234567</id:memberCode><id:subsystemCode>consumer</id:subsystemCode></xroad:client><xroad:service id:objectType="SERVICE"><id:xRoadInstance>EXAMPLE</id:xRoadInstance><id:memberClass>GOV</id:memberClass><id:memberCode>7654321</id:memberCode><id:subsystemCode>producer</id:subsystemCode><id:serviceCode>getRandom</id:serviceCode><id:serviceVersion>v1</id:serviceVersion></xroad:service><xroad:id>8645ab00-e269-4af2-b7e8-e1fafb5949aa</xroad:id><xroad:protocolVersion>4.0</xroad:protocolVersion></SOAP-ENV:Header><SOAP-ENV:Body><getRandom xmlns="http://example.org/producer"/></SOAP-ENV:Body></SOAP-ENV:Envelope>';

const SOAP_VIEW: MessageView = {
  kind: 'soap',
  direction: 'request',
  fields: [
    { label: 'Client', value: 'SUBSYSTEM:EXAMPLE/GOV/1234567/consumer' },
    { label: 'Service', value: 'SERVICE:EXAMPLE/GOV/7654321/producer/getRandom/v1' },
    { label: 'Query ID', value: '8645ab00-e269-4af2-b7e8-e1fafb5949aa' },
    { label: 'Protocol version', value: '4.0' },
  ],
  restLine: null,
  rawMessage: SOAP_XML,
  attachments: [],
};

const REST_MESSAGE = [
  '200',
  'OK',
  'Date:Thu, 15 Jan 2026 10:15:32 GMT',
  'Content-Type:application/json',
  'x-road-id:EXAMPLE-42ec0513-2363-46da-a1d6-1f38b7e37a45',
  'x-road-client:EXAMPLE/GOV/1234567/consumer',
  'x-road-service:EXAMPLE/GOV/7654321/petstore/inventory',
  'x-road-request-id:bd769b62-821b-47cc-8214-06a1c8b22f8f',
  'x-road-request-hash:zg29AwCUd8d74QtZFGIBO3x9dFatbvJXJG5mllReJ3gWwEemaiSI5qGeUVt+aaq606jjKVi2JdcZjdBFT5pbsg==',
  '',
].join('\n');

const restView = (attachment: string): MessageView => ({
  kind: 'rest-response',
  direction: 'response',
  fields: [
    { label: 'Client', value: 'SUBSYSTEM:EXAMPLE/GOV/1234567/consumer' },
    { label: 'Service', value: 'SERVICE:EXAMPLE/GOV/7654321/petstore/inventory' },
    { label: 'Query ID', value: 'EXAMPLE-42ec0513-2363-46da-a1d6-1f38b7e37a45' },
    { label: 'Request ID', value: 'bd769b62-821b-47cc-8214-06a1c8b22f8f' },
  ],
  restLine: '200 OK',
  rawMessage: REST_MESSAGE,
  attachments: [{ name: 'attachment1', bytes: enc.encode(attachment) }],
});

const PETSTORE_SIGNER = {
  id: 'SUBSYSTEM:EXAMPLE/GOV/7654321/petstore',
  cert: cert(
    '2.5.4.15=GOV,SERIALNUMBER=7654321,CN=Pet Store Ltd,O=Pet Store Ltd,C=XX',
    '8',
    '2026-01-02T00:00:00.000Z',
    '2036-01-02T00:00:00.000Z',
  ),
};

const REST_DIGEST = {
  uri: '/attachment1',
  digestHex:
    '2dd417f693f75f5a399a6d9cedd079663fad4e4f3c54bf74c17a672360a608e07fd5f00e281e95f7e98e700ee6582db122e357ecd7b98b259b2776cbfaa14f93',
};

const CASES: Record<DemoKind, DemoCase> = {
  ok: {
    fileName: '8645ab00-e269-4af2-b7e8-e1fafb5949aa-request.asice',
    size: 16532,
    result: {
      ok: true,
      signer: {
        id: 'MEMBER:EXAMPLE/GOV/1234567',
        cert: cert(
          '2.5.4.15=GOV,SERIALNUMBER=1234567,CN=Example Agency,O=Example Agency,C=XX',
          '7',
          '2026-01-02T00:00:00.000Z',
          '2036-01-02T00:00:00.000Z',
        ),
      },
      ocsp: { ...OCSP, producedAt: '2026-01-15T10:05:10.000Z' },
      timestamp: { signedBy: TSA, genTime: '2026-01-15T10:06:38.000Z' },
      // Batch signature: digests of attachments that are not in this container.
      attachmentDigests: [
        {
          uri: '/attachment1',
          digestHex:
            'f5285ae6797f26c39542633e913e8701fef4d9d9f3ca6e1826d839b94a1af605afd6b7c6150542f5c9080fd56b750749c91631fa3f19283f86428fdebc07375d',
          verified: false,
        },
        {
          uri: '/attachment2',
          digestHex:
            '267abffe7434668c112e09738b869c674c54b3fe6fad094daabf7b4e0ec64949f23b0572b2b16484d117df1c186df6b7bcd98246c89998f7e82aea9e35c28d45',
          verified: false,
        },
      ],
      confVersion: CONF_VERSION,
    },
    message: { status: 'ok', view: SOAP_VIEW },
  },
  'ok-rest': {
    fileName: 'EXAMPLE-42ec0513-2363-46da-a1d6-1f38b7e37a45-response.asice',
    size: 14770,
    result: {
      ok: true,
      signer: PETSTORE_SIGNER,
      ocsp: { ...OCSP, producedAt: '2026-01-15T10:14:58.000Z' },
      timestamp: { signedBy: TSA, genTime: '2026-01-15T10:15:40.000Z' },
      attachmentDigests: [{ ...REST_DIGEST, verified: true }],
      confVersion: CONF_VERSION,
    },
    message: { status: 'ok', view: restView('{"approved":50,"placed":100,"delivered":50}') },
  },
  unverified: {
    fileName: 'tampered-attachment-response.asice',
    size: 14771,
    result: {
      ok: true,
      signer: PETSTORE_SIGNER,
      ocsp: { ...OCSP, producedAt: '2026-01-15T10:14:58.000Z' },
      timestamp: { signedBy: TSA, genTime: '2026-01-15T10:15:40.000Z' },
      // attachment1 is in the container but was edited (tamper case, amber);
      // attachment2 is signed but not stored in the container (normal, neutral).
      attachmentDigests: [
        { ...REST_DIGEST, verified: false },
        {
          uri: '/attachment2',
          digestHex:
            '63b5553de1dde4af3b2936b5f3524e9400c8bb02cfd93bfbee78e4e17a6d50cd9418d964baf11a6eb117b83011d0a697be19c9ee42091e447b442aad30ab6723',
          verified: false,
        },
      ],
      confVersion: CONF_VERSION,
    },
    message: { status: 'ok', view: restView('{"approved":50,"placed":100,"delivered":5000}') },
  },
  fail: {
    fileName: 'tampered-signature-request.asice',
    size: 16532,
    result: {
      ok: false,
      faultCode: 'invalid_signature_value',
      faultString: 'Signature is not valid',
      confVersion: CONF_VERSION,
    },
    message: { status: 'ok', view: SOAP_VIEW },
  },
};

export function demoCase(kind: string | null): DemoCase | null {
  return kind && kind in CASES ? CASES[kind as DemoKind] : null;
}

/** Fake trust-panel state; null = use the live poller. */
export function demoTrust(kind: string | null, now: Date): TrustView | null {
  const base: TrustView = {
    status: 'fresh',
    instanceId: 'EXAMPLE',
    confVersion: CONF_VERSION,
    expireDate: new Date(now.getTime() + 7 * 60_000),
    expired: false,
    lastSuccess: new Date(now.getTime() - 20_000),
    lastAttempt: new Date(now.getTime() - 20_000),
    error: null,
    loading: false,
  };
  switch (kind) {
    case 'fresh':
      return base;
    case 'stale':
      return {
        ...base,
        status: 'stale',
        expired: true,
        expireDate: new Date(now.getTime() - 3 * 60_000),
        lastSuccess: new Date(now.getTime() - 13 * 60_000),
        error: { code: 'FETCH_FAILED', message: 'HTTP 502 for /globalconf/internalconf?version=6', at: base.lastAttempt! },
      };
    case 'failed':
      return {
        ...base,
        status: 'failed',
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'Directory signature does not verify against the configuration anchor',
          at: base.lastAttempt!,
        },
      };
    case 'none':
      return { ...base, status: 'none', instanceId: null, confVersion: null, expireDate: null, lastSuccess: null, loading: true };
    default:
      return null;
  }
}
