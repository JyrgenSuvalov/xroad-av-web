import { zipSync, strToU8 } from 'fflate';
import { describe, expect, it } from 'vitest';
import { readContainer, MIMETYPE } from '../../src/container/read';
import { readZipEntries, DEFAULT_LIMITS } from '../../src/container/zip';
import { CodedError } from '../../src/util/errors';

const SIG_EMBEDDED = `<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><ds:Signature Id="signature"><ds:SignedInfo/><ds:Object><xades:EncapsulatedTimeStamp>QUJD&#13;
REVG</xades:EncapsulatedTimeStamp></ds:Object></ds:Signature></asic:XAdESSignatures>`;

function zip(files: Record<string, string | Uint8Array>): Uint8Array {
  const m: Record<string, Uint8Array> = {};
  for (const [k, v] of Object.entries(files)) m[k] = typeof v === 'string' ? strToU8(v) : v;
  return zipSync(m);
}
const base = () => ({ mimetype: MIMETYPE, 'message.xml': '<m/>', 'META-INF/signatures.xml': SIG_EMBEDDED });

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof CodedError ? e.faultCode : `raw:${String(e)}`;
  }
}

describe('readContainer', () => {
  it('reads a container with embedded timestamp (lenient base64)', async () => {
    const c = await readContainer(zip({ ...base(), attachment1: 'x' }));
    expect(c.timestampSource).toBe('embedded');
    expect(new TextDecoder().decode(c.timestampDer)).toBe('ABCDEF');
    expect(c.attachmentDigests.get('attachment1')?.length).toBe(64);
    expect(c.get('/message.xml')).toBe('<m/>');
  });

  it('prefers META-INF/timestamp.tst', async () => {
    const c = await readContainer(zip({ ...base(), 'META-INF/timestamp.tst': new Uint8Array([1, 2]) }));
    expect(c.timestampSource).toBe('tst');
    expect(c.timestampValue).toBe('AQI=');
  });

  it.each([
    ['non-zip input', () => new Uint8Array([1, 2, 3]), 'asic_mime_type_not_found'],
    ['missing mimetype', () => zip({ ...base(), mimetype: ' \n' }), 'asic_mime_type_not_found'],
    ['bad mimetype (trailing newline)', () => zip({ ...base(), mimetype: MIMETYPE + '\n' }), 'asic_invalid_mime_type'],
    ['mimetype case-insensitive', () => zip({ ...base(), mimetype: MIMETYPE.toUpperCase() }), 'ok'],
    ['MESSAGE.XML is not message.xml', () => { const b: Record<string, string> = base(); delete b['message.xml']; b['MESSAGE.XML'] = '<m/>'; return zip(b); }, 'asic_message_not_found'],
    ['missing signature', () => zip({ mimetype: MIMETYPE, 'message.xml': '<m/>' }), 'asic_signature_not_found'],
    ['sig chain without result', () => zip({ ...base(), 'sig-hashchain.xml': '<a/>' }), 'asic_hash_chain_result_not_found'],
    ['sig result without chain', () => zip({ ...base(), 'sig-hashchainresult.xml': '<a/>' }), 'asic_hash_chain_not_found'],
    ['empty timestamp.tst', () => zip({ ...base(), 'META-INF/timestamp.tst': new Uint8Array() }), 'asic_timestamp_not_found'],
    ['no timestamp anywhere', () => zip({ ...base(), 'META-INF/signatures.xml': SIG_EMBEDDED.replace(/<ds:Object>.*<\/ds:Object>/s, '<ds:Object/>') }), 'malformed_signature'],
    ['no ds:Signature', () => zip({ ...base(), 'META-INF/signatures.xml': '<x/>' }), 'malformed_signature'],
    ['DOCTYPE in signatures.xml', () => zip({ ...base(), 'META-INF/signatures.xml': '<!DOCTYPE x>' + SIG_EMBEDDED }), 'invalid_xml'],
    ['ts chain without result', () => zip({ ...base(), 'ts-hashchain.xml': '<a/>' }), 'asic_hash_chain_result_not_found'],
    ['blank manifest', () => zip({ ...base(), 'META-INF/manifest.xml': ' ' }), 'asic_manifest_not_found'],
  ])('%s', async (_n, mk, expected) => {
    expect(await code(readContainer(mk()))).toBe(expected);
  });

  it('round-trips invalid UTF-8 lossily (U+FFFD) and keeps BOM', async () => {
    const msg = new Uint8Array([0xef, 0xbb, 0xbf, 0x3c, 0xff, 0x3e]);
    const c = await readContainer(zip({ ...base(), 'message.xml': msg }));
    expect(Array.from(c.getBytes('message.xml')!)).toEqual([0xef, 0xbb, 0xbf, 0x3c, 0xef, 0xbf, 0xbd, 0x3e]);
  });
});

describe('zip limits', () => {
  it('rejects oversized entries (zip bomb) while inflating', () => {
    const big = zipSync({ a: new Uint8Array(1_000_000) });
    expect(() => readZipEntries(big, { ...DEFAULT_LIMITS, maxEntryBytes: 1000 })).toThrow(/xrav.limit_exceeded/);
    expect(() => readZipEntries(big, { ...DEFAULT_LIMITS, maxTotalBytes: 1000 })).toThrow(/xrav.limit_exceeded/);
    expect(() => readZipEntries(big, { ...DEFAULT_LIMITS, maxContainerBytes: 10 })).toThrow(/xrav.limit_exceeded/);
  });
  it('detects CRC corruption as io_error', () => {
    const z = zipSync({ a: strToU8('hello') }, { level: 0 });
    const i = Buffer.from(z).indexOf('hello');
    z[i] = 0x48;
    expect(() => readZipEntries(z)).toThrow(/io_error/);
  });
});
