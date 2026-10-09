// certSummary serial (BigInteger.toString of the two's-complement DER INTEGER)
// and validity (UTCTime 50-year pivot, GeneralizedTime, ms ISO strings) on hand-built
// minimal certificates; DER and pkijs inputs give the same summary.
import * as pkijs from 'pkijs';
import { describe, expect, it } from 'vitest';
import { certSummary } from '../../src/result';

const len = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
const tlv = (tag: number, body: number[]) => [tag, ...len(body.length), ...body];
const ascii = (s: string) => [...s].map((c) => c.charCodeAt(0));
const seq = (...items: number[][]) => tlv(0x30, items.flat());
const algId = seq(tlv(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), [0x05, 0x00]); // sha256WithRSA
const cnName = (cn: string) => seq(tlv(0x31, seq(tlv(0x06, [0x55, 0x04, 0x03]), tlv(0x0c, ascii(cn)))));
const utc = (s: string) => tlv(0x17, ascii(s));
const gen = (s: string) => tlv(0x18, ascii(s));

function certDer(serial: number[], notBefore: number[], notAfter: number[]): Uint8Array<ArrayBuffer> {
  const spki = seq(seq(tlv(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), [0x05, 0x00]), tlv(0x03, [0x00, 0x30, 0x00]));
  const tbs = seq(tlv(0xa0, tlv(0x02, [0x02])), tlv(0x02, serial), algId, cnName('Issuer, Ltd'), seq(notBefore, notAfter), cnName(' Subj '), spki);
  return Uint8Array.from(seq(tbs, algId, tlv(0x03, [0x00, 0x01])));
}

const sample = () => certDer([0x01], utc('250101000000Z'), utc('260101000000Z'));

describe('certSummary', () => {
  it('formats subject/issuer as JDK RFC 2253', () => {
    const s = certSummary(sample());
    expect(s.subject).toBe('CN=\\ Subj\\ ');
    expect(s.issuer).toBe('CN=Issuer\\, Ltd');
  });

  it('accepts DER and pkijs.Certificate alike', () => {
    const der = sample();
    expect(certSummary(pkijs.Certificate.fromBER(der))).toEqual(certSummary(der));
  });

  it.each([
    [[0x01], '1'],
    [[0x00, 0xff], '255'],
    [[0xff], '-1'],
    [[0x80, 0x00], '-32768'],
    [[0x00, 0x8f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], '822094670998632891489572718402909198556462055423'],
    [[0x00, 0x00, 0x05], '5'], // non-minimal DER: BigInteger still reads 5
  ])('serial %j → %s', (serial, expected) => {
    expect(certSummary(certDer(serial, utc('250101000000Z'), utc('260101000000Z'))).serialNumber).toBe(expected);
  });

  it('UTCTime pivots at 50 (YY < 50 → 20YY) and prints .000Z', () => {
    const s = certSummary(certDer([1], utc('500101000000Z'), utc('491231235959Z')));
    expect(s.notBefore).toBe('1950-01-01T00:00:00.000Z');
    expect(s.notAfter).toBe('2049-12-31T23:59:59.000Z');
  });

  it('GeneralizedTime (ms kept, finer truncated)', () => {
    const s = certSummary(certDer([1], gen('20500101000000Z'), gen('99991231235959.1239Z')));
    expect(s.notBefore).toBe('2050-01-01T00:00:00.000Z');
    expect(s.notAfter).toBe('9999-12-31T23:59:59.123Z');
  });
});
