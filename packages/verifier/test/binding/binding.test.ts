import { beforeAll, describe, expect, it } from 'vitest';
import { memberEquals, subjectName, verifySignerName } from '../../src/binding';
import { BASIC_PROFILE, getRdnValue, OID_BUSINESS_CATEGORY, OID_SERIAL_NUMBER, signCertProfile } from '../../src/binding/profiles';
import { createClientId, type ClientId } from '../../src/header/ids';
import type { TrustedCert } from '../../src/types';
import { translateException } from '../../src/util/errors';
import { keyUsage, makeCert, nameDer, OID, rsaKey } from '../certpath/helpers';

const BC = OID_BUSINESS_CATEGORY;
const SN = OID_SERIAL_NUMBER;

function codeOf(f: () => unknown): string {
  try {
    f();
    return 'ok';
  } catch (e) {
    const c = translateException(e);
    return `${c.faultCode}: ${c.faultString}`;
  }
}

const certWithSubject = (subjectDer: Uint8Array) => ({ subjectDer }) as TrustedCert;

describe('getRdnValue (BC CertUtils.getRDNValue over the JDK RFC 2253 name)', () => {
  it('returns the LAST matching RDN in DER order', () => {
    const n = nameDer([[[BC, 'first']], [[OID.CN, 'x']], [[BC, 'last']]]);
    expect(getRdnValue(n, BC)).toBe('last');
  });

  it('null when absent', () => expect(getRdnValue(nameDer([[[OID.CN, 'x']]]), SN)).toBeNull());

  it('a multi-valued RDN yields its first AVA, whatever its type', () => {
    const n = nameDer([[[OID.CN, 'cn-value'], [SN, 'sn-value']]]);
    expect(getRdnValue(n, SN)).toBe('cn-value');
  });

  it('values are RFC 2253-escaped', () => {
    expect(getRdnValue(nameDer([[[SN, 'a,b']]]), SN)).toBe('a\\,b');
  });

  it('a non-Name → internal_error', () => {
    expect(codeOf(() => getRdnValue(new Uint8Array([0x05, 0x00]), SN))).toMatch(/^internal_error: /);
  });
});

describe('Basic certificate profile', () => {
  it('builds MEMBER:<instance>/<businessCategory>/<serialNumber>', () => {
    const cert = certWithSubject(nameDer([[[OID.C, 'XX']], [[BC, 'gov']], [[SN, '00000002']], [[OID.CN, 'x']]]));
    expect(BASIC_PROFILE.subjectIdentifier('EXAMPLE', cert)).toMatchObject({
      type: 'MEMBER',
      xRoadInstance: 'EXAMPLE',
      memberClass: 'gov',
      memberCode: '00000002',
      subsystemCode: null,
    });
  });

  it('missing businessCategory / serialNumber → incorrect_certificate', () => {
    expect(codeOf(() => BASIC_PROFILE.subjectIdentifier('i', certWithSubject(nameDer([[[SN, '1']]]))))).toBe(
      'incorrect_certificate: Certificate subject name does not contain business category',
    );
    expect(codeOf(() => BASIC_PROFILE.subjectIdentifier('i', certWithSubject(nameDer([[[BC, 'gov']]]))))).toBe(
      'incorrect_certificate: Certificate subject name does not contain serial number',
    );
  });

  it('an empty member code → internal_error (ClientId validation; " " would be escaped to "\\ ")', () => {
    const cert = certWithSubject(nameDer([[[BC, 'gov']], [[SN, '']]]));
    expect(codeOf(() => BASIC_PROFILE.subjectIdentifier('i', cert))).toMatch(/^internal_error: /);
  });

  it('an unknown profile class → internal_error', () => {
    expect(codeOf(() => signCertProfile('com.example.Nope'))).toBe('internal_error: com.example.Nope could not be found in classpath');
  });
});

describe('memberEquals', () => {
  const m = createClientId('EXAMPLE', 'gov', 'member-25', null);
  it('ignores the subsystem', () => expect(memberEquals(m, createClientId('EXAMPLE', 'gov', 'member-25', 'consumer'))).toBe(true));
  it('is case-sensitive on each member field', () => {
    expect(memberEquals(m, createClientId('example', 'gov', 'member-25', null))).toBe(false);
    expect(memberEquals(m, createClientId('EXAMPLE', 'GOV', 'member-25', null))).toBe(false);
    expect(memberEquals(m, createClientId('EXAMPLE', 'gov', 'MEMBER-25', null))).toBe(false);
  });
});

describe('subjectName key-usage re-check', async () => {
  const key = await rsaKey();
  const subject = [[[BC, 'gov']], [[SN, '1']]] as [string, string][][];
  const signer = createClientId('EXAMPLE', 'gov', '1', null);

  it('no keyUsage → internal_error', async () => {
    const cert = await makeCert({ subject, key });
    expect(codeOf(() => subjectName({} as never, signer, cert, new Date()))).toBe(
      'internal_error: Certificate does not contain keyUsage extension',
    );
  });

  it('keyUsage without nonRepudiation → internal_error', async () => {
    const cert = await makeCert({ subject, key, extensions: [keyUsage([0])] });
    expect(codeOf(() => subjectName({} as never, signer, cert, new Date()))).toBe(
      'internal_error: Certificate must be signing certificate',
    );
  });
});
