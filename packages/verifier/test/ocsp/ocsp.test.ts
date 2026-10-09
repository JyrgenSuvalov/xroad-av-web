import { describe, expect, it } from 'vitest';
import {
  basicResponse,
  javaOffsetDateTime,
  jdkRfc2253,
  jdkX500Equal,
  OcspParseError,
  parseOcspResp,
} from '../../src/ocsp';
import { javaDateTime } from '../../src/ocsp/verify';
import { nameDer, OID } from '../certpath/helpers';

describe('Java time formats', () => {
  it.each([
    ['2026-09-28T17:47:13.000Z', '2026-09-28T17:47:13Z'],
    ['2026-09-28T17:47:00.000Z', '2026-09-28T17:47Z'],
    ['2026-09-28T17:47:00.100Z', '2026-09-28T17:47:00.100Z'],
    ['2026-01-02T03:04:05.006Z', '2026-01-02T03:04:05.006Z'],
  ])('javaOffsetDateTime(%s) = %s', (iso, s) => expect(javaOffsetDateTime(new Date(iso))).toBe(s));

  it('javaDateTime is %tF %tT', () => expect(javaDateTime(new Date('2026-01-02T03:04:05.678Z'))).toBe('2026-01-02 03:04:05'));
});

describe('JDK X500Principal semantics', () => {
  const a = nameDer([[[OID.C, 'XX', 'printable']], [[OID.O, 'Dev Org']], [[OID.CN, 'My  CA']]]);

  it('getName() lists RDNs in reverse DER order', () => expect(jdkRfc2253(a)).toBe('CN=My  CA,O=Dev Org,C=XX'));

  it('unknown attribute types are OID=#hexDER, and specials are escaped', () => {
    const n = nameDer([[[OID.BC, 'gov']], [[OID.CN, 'a,b+c']]]);
    expect(jdkRfc2253(n)).toBe('CN=a\\,b\\+c,2.5.4.15=#0c03676f76');
  });

  it('equals: case-insensitive, whitespace-collapsing, string-type-agnostic', () => {
    const b = nameDer([[[OID.C, 'xx', 'utf8']], [[OID.O, ' dev  org ']], [[OID.CN, 'MY CA']]]);
    expect(jdkX500Equal(a, b)).toBe(true);
  });

  it('equals is RDN-order-sensitive', () => {
    const rev = nameDer([[[OID.CN, 'My  CA']], [[OID.O, 'Dev Org']], [[OID.C, 'XX', 'printable']]]);
    expect(jdkX500Equal(a, rev)).toBe(false);
  });

  it('multi-valued RDN AVAs compare as a set', () => {
    const x = nameDer([[[OID.CN, 'a'], [OID.O, 'b']]]);
    const y = nameDer([[[OID.O, 'b'], [OID.CN, 'a']]]);
    expect(jdkX500Equal(x, y)).toBe(true);
  });
});

describe('OCSP parsing', () => {
  it('rejects garbage', () => {
    expect(() => parseOcspResp(new Uint8Array([1, 2, 3]))).toThrow(OcspParseError);
  });

  it('a non-successful status has no responseBytes', () => {
    // OCSPResponse { responseStatus tryLater(3) }
    const r = parseOcspResp(new Uint8Array([0x30, 0x03, 0x0a, 0x01, 0x03]));
    expect(r).toMatchObject({ responseStatus: 3, responseType: null, responseBytes: null });
    expect(() => basicResponse(r)).toThrow();
  });
});
