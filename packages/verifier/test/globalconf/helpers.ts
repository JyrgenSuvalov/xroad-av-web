import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  type FetchLike,
  buildTrustContext,
  confVersionOf,
  instanceTrust,
  parseAnchor,
  parseSharedParams,
} from '../../src/globalconf/index';
import type { TrustContext } from '../../src/types';

export const VECTORS = join(import.meta.dirname, 'vectors');
/** X-Road 7.8.3 system-test fixture (instance DEV), the base of every vector. */
export const FIXTURE = join(VECTORS, 'xroad-fixture');

export const read = (p: string) => new Uint8Array(readFileSync(p));
export const vector = (name: string) => read(join(VECTORS, name));

export const SP_LOCATION = '/V6/20251110170000548026000/shared-params.xml';
export const fixtureDirectory = () => read(join(FIXTURE, 'V6/internalconf'));
export const fixtureSharedParams = () => read(join(FIXTURE, SP_LOCATION));

export const fixtureAnchor = () => parseAnchor(readFileSync(join(FIXTURE, 'anchor.xml'), 'utf8'));
export const testAnchor = () => parseAnchor(readFileSync(join(VECTORS, 'test-anchor.xml'), 'utf8'));

/** Fixture directory: Expire-date 2035-11-11T03:07:40Z. */
export const V6_EXPIRE = new Date('2035-11-11T03:07:40Z');
export const FRESH = new Date(V6_EXPIRE.getTime() - 5 * 60_000);
export const EXPIRED = new Date(V6_EXPIRE.getTime() + 60_000);

export const V6_SP_PATH = `/globalconf${SP_LOCATION}`;

/** TrustContext built from the fixture's shared-params (instance DEV). */
export function fixtureTrust(): TrustContext {
  const sharedParams = parseSharedParams(fixtureSharedParams());
  const inst = instanceTrust({ sharedParams, confVersion: confVersionOf(SP_LOCATION), expiresAt: V6_EXPIRE });
  return buildTrustContext({ mainInstance: inst.instanceId, instances: [inst], verifyOcspNextUpdate: true });
}

/** Offline fetch over a URL → bytes|status map; records requested URLs. */
export function fakeFetch(routes: Record<string, Uint8Array | number | (() => Uint8Array | number)>): FetchLike & {
  calls: string[];
} {
  const calls: string[] = [];
  const f = async (url: string) => {
    calls.push(url);
    let r = routes[url] ?? 404;
    if (typeof r === 'function') r = r();
    if (typeof r === 'number') {
      const status = r;
      return { ok: false, status, arrayBuffer: async () => new ArrayBuffer(0) };
    }
    const body = r;
    return { ok: true, status: 200, arrayBuffer: async () => body.slice().buffer };
  };
  return Object.assign(f, { calls });
}
