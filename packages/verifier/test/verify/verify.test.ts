// verifyContainer contract: never throws and echoes confVersion.
import { describe, expect, it } from 'vitest';
import { verifyContainer } from '../../src/index';
import { fixtureTrust } from '../globalconf/helpers';

const trust = fixtureTrust();

describe('verifyContainer', () => {
  it('returns a failure (never throws) for non-zip bytes, with confVersion', async () => {
    const r = await verifyContainer(new TextEncoder().encode('not a zip'), trust);
    expect(r.ok).toBe(false);
    expect(r.confVersion).toBe(trust.confVersion);
    if (!r.ok) expect(r.faultCode).toMatch(/^[a-z_.]+$/);
  });

  it('returns a failure for empty input', async () => {
    const r = await verifyContainer(new Uint8Array(), trust);
    expect(r.ok).toBe(false);
  });
});
