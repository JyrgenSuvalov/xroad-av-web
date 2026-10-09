import { describe, expect, it } from 'vitest';
import { ConfPoller, GlobalConfError, type PolledConf, type TimerLike, fetchVerifiedConf } from '../../src/globalconf/index';
import type { TrustContext } from '../../src/types';
import { FRESH, V6_EXPIRE, V6_SP_PATH, fakeFetch, fixtureAnchor, fixtureDirectory, fixtureSharedParams, vector } from './helpers';

const trust = (v: string): TrustContext => ({
  mainInstance: 'EXAMPLE',
  confVersion: v,
  verifyOcspNextUpdate: true,
  visibleInstances: () => [],
});
const conf = (v: string, expire: Date): PolledConf & { v: string } => ({ v, expireDate: expire, trust: trust(v) });

/** Manual clock + timer. */
function harness(results: Array<PolledConf | Error>) {
  let now = FRESH.getTime();
  const pending: Array<{ fn: () => void; at: number }> = [];
  const timer: TimerLike = {
    setTimeout: (fn, ms) => {
      const h = { fn, at: now + ms };
      pending.push(h);
      return h;
    },
    clearTimeout: (h) => {
      const i = pending.indexOf(h as (typeof pending)[0]);
      if (i >= 0) pending.splice(i, 1);
    },
  };
  let i = 0;
  const poller = new ConfPoller({
    load: async () => {
      const r = results[Math.min(i++, results.length - 1)]!;
      if (r instanceof Error) throw r;
      return r;
    },
    clock: () => new Date(now),
    timer,
  });
  return {
    poller,
    pending,
    advance: async (ms: number) => {
      now += ms;
      for (const h of pending.filter((p) => p.at <= now)) {
        pending.splice(pending.indexOf(h), 1);
        h.fn();
      }
      // let the refresh promise chain settle
      for (let k = 0; k < 10; k++) await Promise.resolve();
    },
  };
}

const E = (code: ConstructorParameters<typeof GlobalConfError>[0]) => new GlobalConfError(code, 'test');
const T1 = conf('t1', V6_EXPIRE);
const T2 = conf('t2', new Date(V6_EXPIRE.getTime() + 60_000));

describe('ConfPoller', () => {
  it('starts in none, then fresh after a good load; schedules every 60 s', async () => {
    const h = harness([T1, T2]);
    expect(h.poller.state.status).toBe('none');
    expect(h.poller.trust).toBeNull();
    const s = await h.poller.start();
    expect(s.status).toBe('fresh');
    expect(h.poller.trust?.confVersion).toBe('t1');
    expect(h.pending).toHaveLength(1);
    expect(h.pending[0]!.at - FRESH.getTime()).toBe(60_000);
    await h.advance(60_000);
    expect(h.poller.state.status).toBe('fresh');
    expect(h.poller.trust?.confVersion).toBe('t2');
    h.poller.stop();
    expect(h.pending).toHaveLength(0);
  });

  it('fresh → stale when the clock passes Expire-date, without a refresh', async () => {
    const h = harness([T1]);
    await h.poller.refresh();
    expect(h.poller.state.status).toBe('fresh');
    await h.advance(6 * 60_000); // FRESH is Expire-date − 5 min
    const s = h.poller.state;
    expect(s).toMatchObject({ status: 'stale', expired: true, error: null });
    expect(s.conf).toBe(T1); // still usable
  });

  it('refresh error → stale, keeps last good; recovers to fresh', async () => {
    const h = harness([T1, E('FETCH_FAILED'), T2]);
    await h.poller.refresh();
    const s = await h.poller.refresh();
    expect(s).toMatchObject({ status: 'stale', expired: false, error: { code: 'FETCH_FAILED' } });
    expect(s.conf).toBe(T1);
    expect((await h.poller.refresh()).status).toBe('fresh');
  });

  it('signature failure on refresh after a good conf → failed, verification disabled', async () => {
    for (const code of ['SIGNATURE_INVALID', 'VERIFICATION_CERT_NOT_FOUND', 'PART_HASH_MISMATCH', 'INSTANCE_MISMATCH'] as const) {
      const h = harness([T1, E(code), E('FETCH_FAILED')]);
      await h.poller.refresh();
      const s = await h.poller.refresh();
      expect(s).toMatchObject({ status: 'failed', conf: null, error: { code } });
      expect(s.lastGood).toBe(T1);
      expect(h.poller.trust).toBeNull();
      // A later fetch error does not mask the hard failure.
      expect(await h.poller.refresh()).toMatchObject({ status: 'failed', error: { code } });
    }
  });

  it('failed recovers only with a fully verified, non-rollback configuration', async () => {
    const h = harness([T1, E('SIGNATURE_INVALID'), T2]);
    await h.poller.refresh();
    await h.poller.refresh();
    expect((await h.poller.refresh()).status).toBe('fresh');
    expect(h.poller.trust?.confVersion).toBe('t2');
  });

  it('first load: fetch error → none; malformed → failed', async () => {
    const a = harness([E('FETCH_FAILED')]);
    expect(await a.poller.refresh()).toMatchObject({ status: 'none', error: { code: 'FETCH_FAILED' } });
    const b = harness([E('DIRECTORY_MALFORMED')]);
    expect(await b.poller.refresh()).toMatchObject({ status: 'failed', error: { code: 'DIRECTORY_MALFORMED' } });
    const c = harness([T1, E('DIRECTORY_MALFORMED')]);
    await c.poller.refresh();
    expect(await c.poller.refresh()).toMatchObject({ status: 'stale', error: { code: 'DIRECTORY_MALFORMED' } });
  });

  it('V13: rollback to an older Expire-date → stale (ROLLBACK), current conf kept', async () => {
    const h = harness([T2, T1]);
    await h.poller.refresh();
    const s = await h.poller.refresh();
    expect(s).toMatchObject({ status: 'stale', error: { code: 'ROLLBACK' } });
    expect(s.conf).toBe(T2);
  });

  it('concurrent refresh() calls share one load', async () => {
    let loads = 0;
    const p = new ConfPoller({ load: async () => (loads++, T1), clock: () => FRESH });
    await Promise.all([p.refresh(), p.refresh()]);
    expect(loads).toBe(1);
  });

  it('notifies subscribers', async () => {
    const h = harness([T1]);
    const seen: string[] = [];
    const off = h.poller.subscribe((s) => seen.push(s.status));
    await h.poller.refresh();
    off();
    await h.poller.refresh();
    expect(seen).toEqual(['fresh']);
  });

  it('integration: real fetchVerifiedConf, then a re-signed (wrong-key) directory → failed', async () => {
    let dir = fixtureDirectory();
    const f = fakeFetch({ '/globalconf/internalconf?version=6': () => dir, [V6_SP_PATH]: fixtureSharedParams() });
    const p = new ConfPoller({ load: () => fetchVerifiedConf(f, fixtureAnchor(), { now: FRESH }), clock: () => FRESH });
    expect((await p.refresh()).status).toBe('fresh');
    dir = vector('resigned.internalconf');
    expect(await p.refresh()).toMatchObject({ status: 'failed', error: { code: 'VERIFICATION_CERT_NOT_FOUND' } });
  });
});
