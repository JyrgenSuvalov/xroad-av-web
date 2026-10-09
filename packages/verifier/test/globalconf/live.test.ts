// V15: live fetch through the dev proxy / nginx (manual, CI-optional).
//   pnpm dev   # then:
//   XRAV_LIVE_URL=http://localhost:5173 pnpm --filter @xrav/verifier exec vitest run test/globalconf/live
import { describe, expect, it } from 'vitest';
import { fetchVerifiedConf, loadAnchor } from '../../src/globalconf/index';

const base = process.env.XRAV_LIVE_URL;

describe.skipIf(!base)('live globalconf through proxy', () => {
  it('loads anchor, fetches + verifies directory and shared-params', async () => {
    const f = (url: string, init?: { signal?: AbortSignal }) => fetch(new URL(url, base), init);
    const anchor = await loadAnchor(f);
    const c = await fetchVerifiedConf(f, anchor);
    const [inst] = c.trust.visibleInstances(new Date());
    const summary = {
      directoryUrl: c.directoryUrl,
      version: c.directory.version,
      expireDate: c.directory.expireDateText,
      confVersion: c.confVersion,
      mainInstance: c.trust.mainInstance,
      fresh: Date.now() <= c.expireDate.getTime(),
      cas: inst!.approvedCas.map((a) => a.caName),
      tsas: c.sharedParams.approvedTSAs.map((t) => t.name),
      ocspFreshnessSeconds: inst!.ocspFreshnessSeconds,
      members: c.sharedParams.members.length,
    };
    console.log('LIVE', JSON.stringify(summary));
    expect(c.directory.version).toBe(6);
    expect(summary.fresh).toBe(true);
  }, 60_000);
});
