import { describe, expect, it } from 'vitest';
import { GlobalConfError, parseAnchor, verifyDirectory } from '../../src/globalconf/index';
import { EXPIRED, FRESH, SP_LOCATION, fixtureAnchor, fixtureDirectory, testAnchor, vector } from './helpers';

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(GlobalConfError);
    return (e as GlobalConfError).code;
  }
  return 'OK';
}

describe('parseAnchor', () => {
  it('parses the X-Road fixture anchor', () => {
    const a = fixtureAnchor();
    expect(a.instanceIdentifier).toBe('DEV');
    expect(a.sources.map((s) => s.downloadURL)).toEqual(['http://cs/internalconf', 'https://cs/internalconf']);
    expect(a.sources[0]!.verificationCerts).toHaveLength(1);
    expect(a.sources[0]!.verificationCerts[0]![0]).toBe(0x30); // DER SEQUENCE
  });

  it('accepts any root prefix and line-wrapped certs', () => {
    const xml = `<tns:configurationAnchor xmlns:tns="http://x-road.eu/xsd/xroad.xsd">
      <instanceIdentifier>EE</instanceIdentifier>
      <source><downloadURL>http://x/internalconf</downloadURL>
      <verificationCert>MIIB
      AAAA</verificationCert></source></tns:configurationAnchor>`;
    expect(parseAnchor(xml).sources[0]!.verificationCerts[0]).toHaveLength(6);
  });

  it.each([
    ['wrong namespace', '<configurationAnchor><instanceIdentifier>x</instanceIdentifier></configurationAnchor>'],
    ['no source', '<a:configurationAnchor xmlns:a="http://x-road.eu/xsd/xroad.xsd"><instanceIdentifier>x</instanceIdentifier></a:configurationAnchor>'],
    ['not XML', 'garbage <<<'],
    ['DOCTYPE', '<!DOCTYPE x [<!ENTITY a "b">]><x/>'],
  ])('rejects %s with ANCHOR_INVALID', (_, xml) => {
    expect(() => parseAnchor(xml)).toThrowError(expect.objectContaining({ code: 'ANCHOR_INVALID' }));
  });
});

describe('verifyDirectory', () => {
  it('V1: valid V6 directory', async () => {
    const d = await verifyDirectory(fixtureDirectory(), fixtureAnchor(), { now: FRESH, expectedVersion: 6 });
    expect(d.version).toBe(6);
    expect(d.expireDateText).toBe('2035-11-11T03:07:40Z');
    expect(d.expireDate.toISOString()).toBe('2035-11-11T03:07:40.000Z');
    expect(d.signatureAlgorithmId).toBe('http://www.w3.org/2001/04/xmldsig-more#rsa-sha512');
    expect(d.parts.map((p) => p.contentIdentifier)).toEqual(['SHARED-PARAMETERS', 'PRIVATE-PARAMETERS']);
    expect(d.sharedParams).toMatchObject({
      instance: 'DEV',
      contentLocation: SP_LOCATION,
      hashAlgorithmId: 'http://www.w3.org/2001/04/xmlenc#sha512',
    });
    expect(d.sharedParams.hash).toHaveLength(64);
    expect(d.nextUpdate).toBeUndefined();
  });


  it('V3: expired directory still verifies (expiry is the caller’s amber flag)', async () => {
    const d = await verifyDirectory(fixtureDirectory(), fixtureAnchor(), { now: EXPIRED });
    expect(d.expireDate.getTime()).toBeLessThan(EXPIRED.getTime());
    const old = await verifyDirectory(vector('expired-2020.internalconf'), testAnchor(), { now: FRESH });
    expect(old.expireDateText).toBe('2020-01-01T00:00:00Z');
  });

  it('V9: re-signed directory verifies with the test anchor', async () => {
    const d = await verifyDirectory(vector('resigned.internalconf'), testAnchor(), { now: FRESH });
    expect(d.version).toBe(6);
  });

  it('V4: directory signed by a different key → VERIFICATION_CERT_NOT_FOUND', async () => {
    expect(await code(verifyDirectory(vector('resigned.internalconf'), fixtureAnchor(), { now: FRESH }))).toBe(
      'VERIFICATION_CERT_NOT_FOUND',
    );
  });

  it('V5: different key with the anchor cert hash forged → SIGNATURE_INVALID', async () => {
    expect(await code(verifyDirectory(vector('forged-hash.internalconf'), fixtureAnchor(), { now: FRESH }))).toBe(
      'SIGNATURE_INVALID',
    );
  });

  it('V6: one tampered byte in the signed data → SIGNATURE_INVALID', async () => {
    expect(await code(verifyDirectory(vector('tampered-expire.internalconf'), fixtureAnchor(), { now: FRESH }))).toBe(
      'SIGNATURE_INVALID',
    );
  });

  it('every single-byte flip inside the signed region fails', async () => {
    const orig = fixtureDirectory();
    const text = new TextDecoder().decode(orig);
    const start = text.indexOf('--CNo5');
    const end = text.indexOf('--CNo5S3hBEIHbDGmANPgi--') + '--CNo5S3hBEIHbDGmANPgi--\r\n'.length;
    for (const off of [start, start + 30, Math.floor((start + end) / 2), end - 1]) {
      const t = orig.slice();
      t[off] = t[off]! ^ 0x01;
      expect(await code(verifyDirectory(t, fixtureAnchor(), { now: FRESH }))).not.toBe('OK');
    }
  });

  it('anchor cert not valid at `now` → VERIFICATION_CERT_NOT_FOUND', async () => {
    const r = verifyDirectory(fixtureDirectory(), fixtureAnchor(), { now: new Date('2039-01-01T00:00:00Z') });
    expect(await code(r)).toBe('VERIFICATION_CERT_NOT_FOUND');
  });

  it('V8: SHARED-PARAMETERS hash body edited and re-signed → verifies here; the hash check is in fetch', async () => {
    const d = await verifyDirectory(vector('part-hash-resigned.internalconf'), testAnchor(), { now: FRESH });
    expect(d.sharedParams.hash).toHaveLength(64);
  });

  it('V10: instance mismatch → INSTANCE_MISMATCH', async () => {
    expect(await code(verifyDirectory(vector('instance-other.internalconf'), testAnchor(), { now: FRESH }))).toBe(
      'INSTANCE_MISMATCH',
    );
  });

  it.each([
    ['no-expire.internalconf', 'DIRECTORY_MALFORMED'],
    ['bad-expire.internalconf', 'DIRECTORY_MALFORMED'],
    ['cte-uppercase.internalconf', 'DIRECTORY_MALFORMED'],
    ['two-shared.internalconf', 'DIRECTORY_MALFORMED'],
    ['unknown-sigalg.internalconf', 'UNSUPPORTED_ALGORITHM'],
    ['location-evil-host.internalconf', 'DIRECTORY_MALFORMED'],
    ['location-dotdot.internalconf', 'DIRECTORY_MALFORMED'],
  ])('V11/V12: %s → %s', async (file, expected) => {
    expect(await code(verifyDirectory(vector(file), testAnchor(), { now: FRESH }))).toBe(expected);
  });

  it('Version header must match the requested version', async () => {
    const v = vector('version-5.internalconf');
    expect(await code(verifyDirectory(v, testAnchor(), { now: FRESH, expectedVersion: 6 }))).toBe('DIRECTORY_MALFORMED');
    expect((await verifyDirectory(v, testAnchor(), { now: FRESH, expectedVersion: 5 })).version).toBe(5);
  });

  describe('structural damage', () => {
    const v6 = () => new TextDecoder('latin1').decode(fixtureDirectory());
    const enc = (s: string) => new Uint8Array([...s].map((c) => c.charCodeAt(0)));
    const run = (s: string) => code(verifyDirectory(enc(s), fixtureAnchor(), { now: FRESH }));

    it('truncated body → DIRECTORY_MALFORMED', async () => {
      expect(await run(v6().slice(0, 900))).toBe('DIRECTORY_MALFORMED');
    });
    it('missing signature part → DIRECTORY_MALFORMED', async () => {
      const s = v6();
      const i = s.lastIndexOf('\r\n--lmyAPTb9i7P4fQ7MmpnZ\r\n');
      expect(await run(s.slice(0, i) + '\r\n--lmyAPTb9i7P4fQ7MmpnZ--\r\n')).toBe('DIRECTORY_MALFORMED');
    });
    it('LF-only line endings → DIRECTORY_MALFORMED', async () => {
      expect(await run(v6().replace(/\r\n/g, '\n'))).toBe('DIRECTORY_MALFORMED');
    });
    it('not multipart/related → DIRECTORY_MALFORMED', async () => {
      expect(await run(v6().replace('multipart/related', 'text/plain'))).toBe('DIRECTORY_MALFORMED');
    });
    it('signature part with wrong Content-Transfer-Encoding → SIGNATURE_MALFORMED', async () => {
      expect(await run(v6().replace('Content-Transfer-Encoding: base64', 'Content-Transfer-Encoding: BASE64'))).toBe(
        'SIGNATURE_MALFORMED',
      );
    });
    it('missing Verification-certificate-hash → SIGNATURE_MALFORMED', async () => {
      expect(await run(v6().replace('Verification-certificate-hash', 'X-Hash'))).toBe('SIGNATURE_MALFORMED');
    });
    it('empty input → DIRECTORY_MALFORMED', async () => {
      expect(await run('')).toBe('DIRECTORY_MALFORMED');
    });
  });

});
