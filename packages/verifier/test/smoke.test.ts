import { describe, expect, it } from 'vitest';
import { verifyContainer } from '../src/index';

describe('scaffold', () => {
  it('verifyContainer returns a fault result for empty input', async () => {
    const r = await verifyContainer(new Uint8Array(), {
      mainInstance: 'test',
      confVersion: 'test',
      verifyOcspNextUpdate: true,
      visibleInstances: () => [],
    });
    expect(r).toEqual({
      ok: false,
      faultCode: expect.stringMatching(/^[a-z_.]+$/),
      faultString: expect.any(String),
      confVersion: 'test',
    });
  });

  it('WebCrypto is available via globalThis.crypto', async () => {
    const d = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode('abc'));
    expect(Buffer.from(d).toString('hex')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
