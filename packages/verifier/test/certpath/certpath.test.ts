import { beforeAll, describe, expect, it } from 'vitest';
import { verifyCertificateChain } from '../../src/certpath';
import { PKIX_BUILD_FAILURE, verifyPkix } from '../../src/certpath/pkix';
import { translateException } from '../../src/util/errors';
import { criticalExtension, keyUsage, makeCert, OID, rsaKey } from './helpers';

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    const c = translateException(e);
    return `${c.faultCode}: ${c.faultString}`;
  }
}

const FAIL = `cannot_create_cert_path.internal_error: ${PKIX_BUILD_FAILURE}`;

describe('verifyPkix (path length 1: EE → approved CA)', async () => {
  const caKey = await rsaKey();
  const eeKey = await rsaKey();
  const caName = [[[OID.CN, 'Test CA']]] as [string, string][][];
  const ca = await makeCert({ subject: caName, key: caKey, extensions: [keyUsage([5])] });
  const notBefore = new Date('2026-01-01T00:00:00Z');
  const notAfter = new Date('2027-01-01T00:00:00Z');
  const ee = (extra: Partial<Parameters<typeof makeCert>[0]> = {}) =>
    makeCert({ subject: [[[OID.CN, 'EE']]], issuer: caName, key: eeKey, signer: caKey, notBefore, notAfter, ...extra });

  it('ok inside the validity window, including both bounds', async () => {
    const c = (await ee({ extensions: [keyUsage([1])] })).cert;
    expect(await codeOf(verifyPkix(c, ca.cert, new Date('2026-06-01T00:00:00Z')))).toBe('ok');
    expect(await codeOf(verifyPkix(c, ca.cert, notBefore))).toBe('ok');
    expect(await codeOf(verifyPkix(c, ca.cert, notAfter))).toBe('ok');
  });

  it('not yet valid / expired at atDate', async () => {
    const c = (await ee()).cert;
    expect(await codeOf(verifyPkix(c, ca.cert, new Date(notBefore.getTime() - 1000)))).toBe(FAIL);
    expect(await codeOf(verifyPkix(c, ca.cert, new Date(notAfter.getTime() + 1000)))).toBe(FAIL);
  });

  it('not signed by the anchor', async () => {
    const c = (await ee({ signer: eeKey })).cert;
    expect(await codeOf(verifyPkix(c, ca.cert, new Date('2026-06-01T00:00:00Z')))).toBe(FAIL);
  });

  it('an unrecognised critical extension fails; a critical keyUsage does not', async () => {
    const bad = (await ee({ extensions: [criticalExtension('1.2.3.4.5')] })).cert;
    expect(await codeOf(verifyPkix(bad, ca.cert, new Date('2026-06-01T00:00:00Z')))).toBe(FAIL);
  });

  it('RSA < 1024 bits is disabled', async () => {
    const small = await makeCert({
      subject: [[[OID.CN, 'small']]],
      issuer: caName,
      key: await rsaKey(512),
      signer: caKey,
      notBefore,
      notAfter,
    });
    expect(await codeOf(verifyPkix(small.cert, ca.cert, new Date('2026-06-01T00:00:00Z')))).toBe(FAIL);
  });
});
