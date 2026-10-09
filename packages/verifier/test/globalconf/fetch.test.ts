import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { GlobalConfError, fetchVerifiedConf, loadAnchor } from '../../src/globalconf/index';
import {
  FRESH,
  V6_EXPIRE,
  V6_SP_PATH,
  VECTORS,
  fakeFetch,
  fixtureAnchor,
  fixtureDirectory,
  fixtureSharedParams,
  read,
  testAnchor,
  vector,
} from './helpers';

const DIR = '/globalconf/internalconf';

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(GlobalConfError);
    return (e as GlobalConfError).code;
  }
  return 'OK';
}

describe('fetchVerifiedConf', () => {
  it('V1: fetches ?version=6, verifies directory + shared-params hash, builds TrustContext', async () => {
    const f = fakeFetch({ [`${DIR}?version=6`]: fixtureDirectory(), [V6_SP_PATH]: fixtureSharedParams() });
    const c = await fetchVerifiedConf(f, fixtureAnchor(), { now: FRESH });
    expect(f.calls).toEqual([`${DIR}?version=6`, V6_SP_PATH]);
    expect(c.directoryUrl).toBe(`${DIR}?version=6`);
    expect(c.directory.version).toBe(6);
    expect(c.confVersion).toBe('V6/20251110170000548026000');
    expect(c.expireDate.toISOString()).toBe(V6_EXPIRE.toISOString());
    expect(c.verifyOcspNextUpdate).toBe(true);
    expect(c.trust.mainInstance).toBe('DEV');
    expect(c.trust.confVersion).toBe(c.confVersion);
    const [inst] = c.trust.visibleInstances(FRESH);
    expect(inst!.approvedCas).toHaveLength(2);
    expect(inst!.tsaCerts).toHaveLength(1);
    expect(inst!.ocspFreshnessSeconds).toBe(3600);
    expect(inst!.expiresAt).toBe(V6_EXPIRE.toISOString());
  });

  it('steps down on 404 only ', async () => {
    const f = fakeFetch({ [`${DIR}?version=5`]: vector('version-5.internalconf'), [V6_SP_PATH]: fixtureSharedParams() });
    const c = await fetchVerifiedConf(f, testAnchor(), { now: FRESH });
    expect(f.calls).toEqual([`${DIR}?version=6`, `${DIR}?version=5`, V6_SP_PATH]);
    expect(c.directory.version).toBe(5);
  });

  it('does not step down on a non-404 error', async () => {
    const f = fakeFetch({ [`${DIR}?version=6`]: 500 });
    expect(await code(fetchVerifiedConf(f, fixtureAnchor(), { now: FRESH }))).toBe('FETCH_FAILED');
    expect(f.calls).toEqual([`${DIR}?version=6`]);
  });

  it('network error → FETCH_FAILED', async () => {
    const f = async () => {
      throw new TypeError('Failed to fetch');
    };
    expect(await code(fetchVerifiedConf(f, fixtureAnchor(), { now: FRESH }))).toBe('FETCH_FAILED');
  });

  it('timeout aborts the request → FETCH_FAILED', async () => {
    const f = (_url: string, init?: { signal?: AbortSignal }) =>
      new Promise<never>((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted'))));
    expect(await code(fetchVerifiedConf(f, fixtureAnchor(), { now: FRESH, timeoutMs: 10 }))).toBe('FETCH_FAILED');
  });

  it('V7: one byte changed in shared-params → PART_HASH_MISMATCH', async () => {
    const f = fakeFetch({ [`${DIR}?version=6`]: fixtureDirectory(), [V6_SP_PATH]: vector('shared-params-tampered.xml') });
    expect(await code(fetchVerifiedConf(f, fixtureAnchor(), { now: FRESH }))).toBe('PART_HASH_MISMATCH');
  });

  it('V8: re-signed directory with a wrong SHARED-PARAMETERS hash → PART_HASH_MISMATCH', async () => {
    const f = fakeFetch({ [`${DIR}?version=6`]: vector('part-hash-resigned.internalconf'), [V6_SP_PATH]: fixtureSharedParams() });
    expect(await code(fetchVerifiedConf(f, testAnchor(), { now: FRESH }))).toBe('PART_HASH_MISMATCH');
  });

  it('V4: wrong signing key → VERIFICATION_CERT_NOT_FOUND, shared-params never fetched', async () => {
    const f = fakeFetch({ [`${DIR}?version=6`]: vector('resigned.internalconf'), [V6_SP_PATH]: fixtureSharedParams() });
    expect(await code(fetchVerifiedConf(f, fixtureAnchor(), { now: FRESH }))).toBe('VERIFICATION_CERT_NOT_FOUND');
    expect(f.calls).toEqual([`${DIR}?version=6`]);
  });

  it('part 404 → re-fetches the directory once ', async () => {
    let n = 0;
    const f = fakeFetch({
      [`${DIR}?version=6`]: fixtureDirectory(),
      [V6_SP_PATH]: () => (n++ === 0 ? 404 : fixtureSharedParams()),
    });
    await fetchVerifiedConf(f, fixtureAnchor(), { now: FRESH });
    expect(f.calls).toEqual([`${DIR}?version=6`, V6_SP_PATH, `${DIR}?version=6`, V6_SP_PATH]);
    const g = fakeFetch({ [`${DIR}?version=6`]: fixtureDirectory() });
    expect(await code(fetchVerifiedConf(g, fixtureAnchor(), { now: FRESH }))).toBe('FETCH_FAILED');
  });

  it('custom base prefix', async () => {
    const f = fakeFetch({
      '/x/gc/internalconf?version=6': fixtureDirectory(),
      [V6_SP_PATH.replace('/globalconf', '/x/gc')]: fixtureSharedParams(),
    });
    await fetchVerifiedConf(f, fixtureAnchor(), { now: FRESH, base: '/x/gc/' });
  });

});

describe('loadAnchor', () => {
  it('loads /anchor.xml', async () => {
    const f = fakeFetch({ '/anchor.xml': read(join(VECTORS, 'test-anchor.xml')) });
    expect((await loadAnchor(f)).instanceIdentifier).toBe('DEV');
  });
  it('404 → ANCHOR_INVALID', async () => {
    expect(await code(loadAnchor(fakeFetch({})))).toBe('ANCHOR_INVALID');
  });
});
