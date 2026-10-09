// nameToRfc2253 vs JDK 21 X500Principal.getName(RFC2253) on hand-built and
// seeded-fuzz DER Names. Expectations come from a JDK probe; "error" = the JDK threw.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodeUtf8Java, nameToRfc2253 } from '../../src/result/rfc2253';

type Vector = { label: string; hex: string; expected?: string; error?: string };
const vectors: Vector[] = JSON.parse(readFileSync(join(__dirname, 'rfc2253-vectors.json'), 'utf8'));
const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));

describe('nameToRfc2253 (JDK probe vectors)', () => {
  it('has the probe vectors', () => expect(vectors.length).toBeGreaterThan(600));

  it.each(vectors.map((v) => [v.label, v] as const))('%s', (_l, v) => {
    if (v.error) expect(() => nameToRfc2253(fromHex(v.hex))).toThrow();
    else expect(nameToRfc2253(fromHex(v.hex))).toBe(v.expected);
  });
});

describe('nameToRfc2253 structure errors', () => {
  it.each([
    ['empty input', ''],
    ['not a SEQUENCE', '3100'],
    ['trailing data', '300000'],
    ['truncated', '3005310330'],
    ['indefinite length', '3080'],
    ['AVA without value', '3007310530030603550403'.slice(0, 18)],
  ])('%s throws', (_l, hex) => expect(() => nameToRfc2253(fromHex(hex))).toThrow());
});

describe('decodeUtf8Java', () => {
  it('decodes valid UTF-8 like TextDecoder', () => {
    const s = 'aÕ€😀';
    expect(decodeUtf8Java(new TextEncoder().encode(s))).toBe(s);
  });
  it('encoded surrogate → one U+FFFD (WHATWG gives three)', () => {
    expect(decodeUtf8Java(Uint8Array.of(0xed, 0xa0, 0x80))).toBe('�');
  });
});
