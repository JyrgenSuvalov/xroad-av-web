// Timestamp unit tests: BC X500Name equality, token parse fault codes (as probed
// against the jar), genTime truncation, and TrustQueries.
import * as asn1js from 'asn1js';
import { describe, expect, it } from 'vitest';
import { parseTimestampToken } from '../../src/timestamp/token';
import { generalizedTime } from '../../src/trust/der';
import { trustQueries } from '../../src/trust/queries';
import { x500Equal } from '../../src/trust/x500';
import type { InstanceTrust, TrustContext } from '../../src/types';
import { isCodedError } from '../../src/util/errors';
import { fixtureTrust } from '../globalconf/helpers';

const now = new Date();
const snapshot = fixtureTrust();
const main = snapshot.visibleInstances(now).find((i) => i.instanceId === snapshot.mainInstance)!;

function ctxWith(patch: Partial<InstanceTrust>): TrustContext {
  return { ...snapshot, visibleInstances: () => [{ ...main, ...patch }] };
}

async function codeOf(p: Promise<unknown> | (() => unknown)): Promise<string | null> {
  try {
    await (typeof p === 'function' ? p() : p);
    return null;
  } catch (e) {
    return isCodedError(e) ? e.faultCode : `non-coded: ${String(e)}`;
  }
}


// ---------------------------------------------------------------- X500
type Av = [oid: string, value: string, type?: 'utf8' | 'printable'];
function name(...rdns: Av[][]): Uint8Array {
  const seq = new asn1js.Sequence({
    value: rdns.map(
      (rdn) =>
        new asn1js.Set({
          value: rdn.map(
            ([oid, v, t]) =>
              new asn1js.Sequence({
                value: [
                  new asn1js.ObjectIdentifier({ value: oid }),
                  t === 'printable' ? new asn1js.PrintableString({ value: v }) : new asn1js.Utf8String({ value: v }),
                ],
              }),
          ),
        }),
    ),
  });
  return new Uint8Array(seq.toBER(false));
}
const C = '2.5.4.6', O = '2.5.4.10', CN = '2.5.4.3';
const baseName = name([[C, 'XX', 'printable']], [[O, 'Example Org']], [[CN, 'Example CA']]);

describe('x500Equal (BC X500Name.equals)', () => {
  it.each([
    ['identical', name([[C, 'XX', 'printable']], [[O, 'Example Org']], [[CN, 'Example CA']]), true],
    ['value case differs', name([[C, 'XX', 'printable']], [[O, 'Example Org']], [[CN, 'example ca']]), true],
    ['internal double space', name([[C, 'XX', 'printable']], [[O, 'Example  Org']], [[CN, 'Example CA']]), true],
    ['leading/trailing space', name([[C, 'XX', 'printable']], [[O, ' Example Org ']], [[CN, 'Example CA']]), true],
    ['UTF8 vs Printable', name([[C, 'XX', 'utf8']], [[O, 'Example Org', 'printable']], [[CN, 'Example CA']]), true],
    ['RDN order reversed', name([[CN, 'Example CA']], [[O, 'Example Org']], [[C, 'XX', 'printable']]), true],
    ['RDN order permuted', name([[O, 'Example Org']], [[C, 'XX', 'printable']], [[CN, 'Example CA']]), true],
    ['missing RDN', name([[O, 'Example Org']], [[CN, 'Example CA']]), false],
    ['extra RDN', name([[C, 'XX', 'printable']], [[O, 'Example Org']], [[O, 'x']], [[CN, 'Example CA']]), false],
    ['different value', name([[C, 'XX', 'printable']], [[O, 'Example Org']], [[CN, 'Example TSA']]), false],
    ['different OID', name([[C, 'XX', 'printable']], [['2.5.4.11', 'Example Org']], [[CN, 'Example CA']]), false],
    ['not a Name', new Uint8Array([2, 1, 0]), false],
  ] as const)('%s → %s', (_l, other, expected) => {
    expect(x500Equal(baseName, other)).toBe(expected);
    expect(x500Equal(other, baseName)).toBe(expected);
  });

  it('non-ASCII case is NOT folded (BC lowercases ASCII only)', () => {
    expect(x500Equal(name([[O, 'ÉCOLE']]), name([[O, 'école']]))).toBe(false);
    expect(x500Equal(name([[O, 'ÉCOLE']]), name([[O, 'École']]))).toBe(true);
  });
});

// ---------------------------------------------------------------- parse
const ascii = (s: string) => new TextEncoder().encode(s);
const contentInfoIdData = new Uint8Array(
  new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }),
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [new asn1js.OctetString({ valueHex: new Uint8Array([1]) })] }),
    ],
  }).toBER(false),
);

describe('parseTimestampToken fault codes (probed against BC 1.84)', () => {
  it.each([
    ['ascii garbage', ascii('hello world, not asn1'), 'io_error'],
    ['single byte 0x30', new Uint8Array([0x30]), 'io_error'],
    ['INTEGER 0', new Uint8Array([2, 1, 0]), 'internal_error'],
    ['empty SEQUENCE', new Uint8Array([0x30, 0]), 'internal_error'],
    ['empty', new Uint8Array(0), 'internal_error'],
    ['ContentInfo(id-data)', contentInfoIdData, 'internal_error'],
  ] as const)('%s → %s', async (_l, der, code) => {
    expect(await codeOf(() => parseTimestampToken(der))).toBe(code);
  });
});

describe('genTime (java.util.Date: ms kept, finer truncated)', () => {
  const gt = (s: string) =>
    generalizedTime(asn1js.fromBER(new Uint8Array([0x18, s.length, ...ascii(s)])).result as asn1js.GeneralizedTime)!.toISOString();
  it.each([
    ['20260101000000.1239Z', '2026-01-01T00:00:00.123Z'],
    ['20260101000000.9999Z', '2026-01-01T00:00:00.999Z'],
    ['20260101000000.5Z', '2026-01-01T00:00:00.500Z'],
    ['20260101000000Z', '2026-01-01T00:00:00.000Z'],
    ['20260101020000+0200', '2026-01-01T00:00:00.000Z'],
  ])('%s → %s', (s, iso) => expect(gt(s)).toBe(iso));
});

// ---------------------------------------------------------------- queries
describe('trustQueries', () => {
  const q = trustQueries(snapshot);
  const tsa = main.tsaCerts[0]!;
  it('tspCertificates = approved TSAs', () => expect(q.tspCertificates(now)).toEqual(main.tsaCerts));
  it('ocspFreshnessSeconds = main instance value', () => expect(q.ocspFreshnessSeconds()).toBe(main.ocspFreshnessSeconds));
  it('getCaCert finds the issuing CA of the TSA cert', () => {
    const ca = q.getCaCert(snapshot.mainInstance, tsa, now);
    expect(x500Equal(ca.cert.subjectDer, new Uint8Array(tsa.cert.issuer.valueBeforeDecode))).toBe(true);
  });
  it('getCaCert: unknown instance / unknown issuer → internal_error', async () => {
    expect(await codeOf(() => q.getCaCert('nope', tsa, now))).toBe('internal_error');
    const selfIssuedCa = main.approvedCas[0]!.cert; // top CA issuer = itself: found
    expect(q.getCaCert(snapshot.mainInstance, selfIssuedCa, now)).toBeTruthy();
    const q2 = trustQueries(ctxWith({ approvedCas: [] }));
    expect(await codeOf(() => q2.getCaCert(snapshot.mainInstance, tsa, now))).toBe('internal_error');
  });
  it('getCaCert: last of BC-equal subjects wins (HashMap put)', () => {
    const a = main.approvedCas[0]!;
    const dup = { ...a, certificateProfileInfo: 'second' };
    const q3 = trustQueries(ctxWith({ approvedCas: [a, dup] }));
    expect(q3.getCaCert(snapshot.mainInstance, tsa, now).certificateProfileInfo).toBe('second');
    expect(q3.allCaCerts(now)).toHaveLength(1);
  });
  it('OCSP responder queries', () => {
    const ca = main.approvedCas.find((c) => c.ocspResponderCerts.length > 0)!;
    const ocsp = ca.ocspResponderCerts[0]!;
    expect(q.ocspResponderCertificates(now)).toContainEqual(ocsp);
    expect(q.isOcspResponderCert(ca.cert, ocsp, now)).toBe(true);
    expect(q.isOcspResponderCert(ocsp, ca.cert, now)).toBe(false);
  });
});
