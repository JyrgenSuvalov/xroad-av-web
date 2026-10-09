import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseNextUpdateParams, parseSharedParams, toTrustedCert } from '../../src/globalconf/index';
import { toHex } from '../../src/util/bytes';
import { FIXTURE, SP_LOCATION, V6_EXPIRE, fixtureSharedParams, fixtureTrust } from './helpers';

const FIVRK = 'ee.ria.xroad.common.certificateprofile.impl.FiVRKCertificateProfileInfoProvider';
const cn = (der: Uint8Array) =>
  toTrustedCert(der)
    .cert.subject.typesAndValues.map((t) => `${t.type}=${t.value.valueBlock.value}`)
    .join(',');
const fixtureXml = () => readFileSync(`${FIXTURE}${SP_LOCATION}`, 'utf8');

describe('parseSharedParams', () => {
  it('X-Road fixture shared-params → CAs, OCSP, TSA, freshness 3600', () => {
    const sp = parseSharedParams(fixtureSharedParams());
    expect(sp.instanceIdentifier).toBe('DEV');
    expect(sp.approvedCAs).toHaveLength(2);
    const ca = sp.approvedCAs[0]!;
    expect(ca).toMatchObject({ authenticationOnly: false, certificateProfileInfo: FIVRK });
    expect(ca.topCA.ocsp[0]!.url).toBe('http://testca:8888');
    // plain base64(DER) certs
    for (const c of sp.approvedCAs) expect(c.topCA.cert[0]).toBe(0x30);
    expect(sp.approvedTSAs).toHaveLength(1);
    expect(sp.approvedTSAs[0]).toMatchObject({ name: 'Test TSA', url: 'http://testca:8899' });
    expect(sp.globalSettings.ocspFreshnessSeconds).toBe(3600);
  });

  it('accepts base64(PEM text) certs too', () => {
    const der = parseSharedParams(fixtureSharedParams()).approvedCAs[0]!.topCA.cert;
    const b64 = Buffer.from(der).toString('base64');
    const pem = `-----BEGIN CERTIFICATE-----\n${b64.replace(/.{64}/g, '$&\n')}\n-----END CERTIFICATE-----\n`;
    const xml = fixtureXml().replace(/(<topCA>\s*<cert>)[^<]+/, (_, open: string) => open + Buffer.from(pem).toString('base64'));
    expect(toHex(parseSharedParams(xml).approvedCAs[0]!.topCA.cert)).toBe(toHex(der));
  });

  it.each([
    ['DOCTYPE', '<!DOCTYPE conf [<!ENTITY x "y">]><conf/>'],
    ['wrong root', '<foo/>'],
    ['bad cert', fixtureXml().replace(/<cert>[^<]{10}/, '<cert>!!!!!!!!!!')],
    ['missing ocspFreshnessSeconds', fixtureXml().replace(/<ocspFreshnessSeconds>.*?<\/ocspFreshnessSeconds>/, '')],
  ])('rejects %s with SHARED_PARAMS_INVALID', (_, xml) => {
    expect(() => parseSharedParams(xml)).toThrowError(expect.objectContaining({ code: 'SHARED_PARAMS_INVALID' }));
  });

  it('nextupdate-params: verifyNextUpdate, default true', () => {
    const ns = 'xmlns:ns3="http://x-road.eu/xsd/xroad.xsd"';
    expect(parseNextUpdateParams(`<ns3:conf ${ns}><verifyNextUpdate>false</verifyNextUpdate></ns3:conf>`)).toBe(false);
    expect(parseNextUpdateParams(`<ns3:conf ${ns}/>`)).toBe(true);
  });
});

describe('instanceTrust + buildTrustContext', () => {
  it('builds the TrustContext from the fixture shared-params', () => {
    const tc = fixtureTrust();
    expect(tc.mainInstance).toBe('DEV');
    expect(tc.confVersion).toBe('V6/20251110170000548026000');
    expect(tc.verifyOcspNextUpdate).toBe(true);
    // Main instance stays visible even long after expiry.
    const [inst, ...rest] = tc.visibleInstances(new Date('2040-01-01T00:00:00Z'));
    expect(rest).toEqual([]);
    expect(inst!.instanceId).toBe('DEV');
    expect(inst!.expiresAt).toBe(V6_EXPIRE.toISOString());
    expect(inst!.ocspFreshnessSeconds).toBe(3600);
    expect(inst!.approvedCas).toHaveLength(2);
    const ca = inst!.approvedCas[0]!;
    expect(ca.certificateProfileInfo).toBe(FIVRK);
    expect(ca.ocspUrls).toEqual(['http://testca:8888']);
    // subjectDer is the DER of the subject Name and equals the cert's own issuer for a self-signed root.
    expect(toHex(ca.cert.subjectDer)).toBe(toHex(new Uint8Array(ca.cert.cert.issuer.toSchema().toBER(false))));
    expect(inst!.tsaCerts).toHaveLength(1);
    expect(cn(inst!.tsaCerts[0]!.der)).toContain('TSA');
  });
});
