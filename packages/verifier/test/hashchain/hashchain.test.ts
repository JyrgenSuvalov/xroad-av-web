import { describe, expect, it } from 'vitest';
import { encodeDigestList } from '../../src/hashchain/der';
import { verifySignatureHashChain, verifyTimestampHashChain } from '../../src/hashchain/asic';
import { verifyHashChain, type HashChainReferenceResolver } from '../../src/hashchain/verifier';
import { encodeUtf8, toHex } from '../../src/util/bytes';
import { CodedError } from '../../src/util/errors';
import {
  batchContainer,
  chainXml,
  dataRef,
  fakeContainer,
  h,
  hashValue,
  resultXml,
  SHA512,
  step,
  stepDigest,
  stepRef,
} from './helpers';

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(CodedError);
    return (e as CodedError).faultCode;
  }
  return 'OK';
}

async function fault(p: Promise<unknown>): Promise<CodedError> {
  try {
    await p;
  } catch (e) {
    return e as CodedError;
  }
  throw new Error('expected a fault');
}

/** Resolver over a map of documents; every URI in the map resolves. */
function mapResolver(docs: Record<string, string>): HashChainReferenceResolver {
  return {
    shouldResolve: (uri) => uri.replace(/^\//, '') in docs,
    resolve: (uri) => {
      const d = docs[uri.replace(/^\//, '')];
      return d === undefined ? null : encodeUtf8(d);
    },
  };
}

describe('DigestList DER', () => {
  it('encodes SEQUENCE OF SEQUENCE { OCTET STRING, UTF8String, SEQUENCE {} }', () => {
    const der = encodeDigestList([{ algorithm: 'u', value: new Uint8Array([1, 2]) }]);
    expect(toHex(der)).toBe('300b' + '3009' + '04020102' + '0c0175' + '3000');
  });
  it('uses long-form lengths', () => {
    const der = encodeDigestList([{ algorithm: SHA512, value: new Uint8Array(200) }]);
    expect(toHex(der.subarray(0, 2))).toBe('3081');
    expect(der.length).toBe(3 + 3 + 3 + 200 + 2 + SHA512.length + 2);
  });
});

describe('verifySignatureHashChain', () => {
  it('accepts a valid chain and labels attachment digests', async () => {
    const { container, a1, a2 } = await batchContainer();
    const lines = await verifySignatureHashChain(container);
    // Attachments are not container entries: digests trusted, labelled verified.
    expect(lines).toEqual([
      { uri: '/attachment1', digestHex: toHex(a1), verified: true },
      { uri: '/attachment2', digestHex: toHex(a2), verified: true },
    ]);
  });

  it('a changed attachment is not a failure, only unverified (parity)', async () => {
    const { container } = await batchContainer({ attachment1: encodeUtf8('tampered') });
    const lines = await verifySignatureHashChain(container);
    expect(lines.map((l) => l.verified)).toEqual([false, true]);
  });

  it('message.xml changed → malformed_signature.invalid_hash_chain_ref', async () => {
    const { container } = await batchContainer({ message: '<Envelope>hellO</Envelope>' });
    const e = await fault(verifySignatureHashChain(container));
    expect(e.faultCode).toBe('malformed_signature.invalid_hash_chain_ref');
    expect(e.faultString).toBe('Invalid digest value in hash chain reference to /message.xml');
  });

  it('result DigestValue changed → malformed_signature.invalid_hash_chain', async () => {
    const { container, chain } = await batchContainer();
    const bad = fakeContainer({
      'message.xml': container.get('message.xml')!,
      'sig-hashchain.xml': chain,
      'sig-hashchainresult.xml': resultXml('/sig-hashchain.xml#STEP0', new Uint8Array(64)),
    });
    expect(await code(verifySignatureHashChain(bad))).toBe('malformed_signature.invalid_hash_chain');
  });

  it('broken structure → malformed_signature.malformed_hash_chain', async () => {
    const { container, result } = await batchContainer();
    for (const chain of [
      chainXml([step('STEP0', '<ns2:Bogus/>')]),
      chainXml([step('STEP0', '<ns2:DataRef URI="/message.xml"/>')]), // DigestValue missing
      chainXml([step('STEP0', '<ns2:DataRef><DigestValue>AA==</DigestValue></ns2:DataRef>')]), // URI missing
      chainXml([step('STEP0', hashValue(new Uint8Array(4)).replace('AAAAAA==', 'A?A='))]), // bad base64
      chainXml([step('STEP0'), step('STEP0')]), // duplicate xs:ID
      chainXml([step('1bad')]), // not an NCName
      chainXml([step('STEP0', 'text')]), // text in element-only content
      '<ns2:HashChain xmlns:ns2="http://cyber.ee/hashchain"><ns2:HashStep id="STEP0"></ns2:HashChain>', // not well-formed
      '<!DOCTYPE x><ns2:HashChain xmlns:ns2="http://cyber.ee/hashchain"/>',
      '<HashChain/>', // wrong namespace
    ]) {
      const c = fakeContainer({
        'message.xml': container.get('message.xml')!,
        'sig-hashchain.xml': chain,
        'sig-hashchainresult.xml': result,
      });
      const e = await fault(verifySignatureHashChain(c));
      expect(e.faultCode, chain).toBe('malformed_signature.malformed_hash_chain');
    }
  });

  it('malformed result document → malformed_signature.malformed_hash_chain', async () => {
    const { container } = await batchContainer();
    const c = fakeContainer({ ...Object.fromEntries(container.entries), 'sig-hashchainresult.xml': '<x/>' });
    expect(await code(verifySignatureHashChain(c))).toBe('malformed_signature.malformed_hash_chain');
  });

  it('chain that does not reference /message.xml → malformed_signature.hashchain_unused_inputs', async () => {
    const d = await h('x');
    const c = fakeContainer({
      'message.xml': '<m/>',
      'sig-hashchain.xml': chainXml([step('STEP0', hashValue(d))]),
      'sig-hashchainresult.xml': resultXml('/sig-hashchain.xml#STEP0', await stepDigest(d)),
    });
    const e = await fault(verifySignatureHashChain(c));
    expect(e.faultCode).toBe('malformed_signature.hashchain_unused_inputs');
    expect(e.faultString).toBe('Some inputs were not referenced by hash chain: /message.xml');
  });

  it('unknown step id / missing fragment → malformed_signature.malformed_hash_chain', async () => {
    const { container, chain, mDigest, a1, a2 } = await batchContainer();
    const digest = await stepDigest(mDigest, a1, a2);
    for (const uri of ['/sig-hashchain.xml#STEP9', '/sig-hashchain.xml', '/sig-hashchain.xml#']) {
      const c = fakeContainer({
        'message.xml': container.get('message.xml')!,
        'sig-hashchain.xml': chain,
        'sig-hashchainresult.xml': resultXml(uri, digest),
      });
      const e = await fault(verifySignatureHashChain(c));
      expect(e.faultCode).toBe('malformed_signature.malformed_hash_chain');
      expect(e.faultString).toBe(`Invalid hash step URI: ${uri}`);
    }
  });

  it('chain document missing → malformed_signature.invalid_reference', async () => {
    const c = fakeContainer({
      'message.xml': '<m/>',
      'sig-hashchainresult.xml': resultXml('/nope.xml#STEP0', new Uint8Array(64)),
    });
    const e = await fault(verifySignatureHashChain(c));
    expect(e.faultCode).toBe('malformed_signature.invalid_reference');
    expect(e.faultString).toBe('Cannot resolve URI: /nope.xml');
  });

  it('no DigestMethod and no DefaultDigestMethod → malformed_signature.internal_error', async () => {
    const m = await h('<m/>');
    const c = fakeContainer({
      'message.xml': '<m/>',
      'sig-hashchain.xml': chainXml([step('STEP0', dataRef('/message.xml', m))], null),
      'sig-hashchainresult.xml': resultXml('/sig-hashchain.xml#STEP0', await stepDigest(m)),
    });
    expect(await code(verifySignatureHashChain(c))).toBe('malformed_signature.internal_error');
  });

  it('result without DigestMethod → malformed_signature.internal_error (Java NPE)', async () => {
    const { container, chain, mDigest, a1, a2 } = await batchContainer();
    const c = fakeContainer({
      'message.xml': container.get('message.xml')!,
      'sig-hashchain.xml': chain,
      'sig-hashchainresult.xml': resultXml('/sig-hashchain.xml#STEP0', await stepDigest(mDigest, a1, a2), null),
    });
    expect(await code(verifySignatureHashChain(c))).toBe('malformed_signature.internal_error');
  });

  it('a HashChain document given as the result → internal_error (JAXB declared-type quirk)', async () => {
    const { container, chain } = await batchContainer();
    const c = fakeContainer({ ...Object.fromEntries(container.entries), 'sig-hashchainresult.xml': chain });
    expect(await code(verifySignatureHashChain(c))).toBe('malformed_signature.internal_error');
  });

  it('unknown digest algorithm → malformed_signature.internal_error', async () => {
    const { container, chain, mDigest, a1, a2 } = await batchContainer();
    const c = fakeContainer({
      'message.xml': container.get('message.xml')!,
      'sig-hashchain.xml': chain,
      'sig-hashchainresult.xml': resultXml('/sig-hashchain.xml#STEP0', await stepDigest(mDigest, a1, a2), 'urn:x'),
    });
    expect(await code(verifySignatureHashChain(c))).toBe('malformed_signature.internal_error');
  });

  it('non-entry, non-attachment DataRef is trusted and labelled unverified', async () => {
    const m = await h('<m/>');
    const other = await h('elsewhere');
    const c = fakeContainer({
      'message.xml': '<m/>',
      'sig-hashchain.xml': chainXml([step('STEP0', dataRef('/message.xml', m), dataRef('/other', other))]),
      'sig-hashchainresult.xml': resultXml('/sig-hashchain.xml#STEP0', await stepDigest(m, other)),
    });
    expect(await verifySignatureHashChain(c)).toEqual([{ uri: '/other', digestHex: toHex(other), verified: false }]);
  });
});

describe('verifyHashChain (multi-step, limits)', () => {
  it('resolves StepRefs within and across chains, memoising shared steps', async () => {
    const msg = '<m/>';
    const m = await h(msg);
    const x = await h('x');
    // other.xml#S: (x); chain.xml#STEP0: (#STEP1, other.xml#S, #STEP1); STEP1: (m)
    const other = chainXml([step('S', hashValue(x))]);
    const s1 = await stepDigest(m);
    const sOther = await stepDigest(x);
    const chain = chainXml([
      step('STEP0', stepRef('#STEP1'), stepRef('/other.xml#S'), stepRef('#STEP1')),
      step('STEP1', dataRef('/message.xml', m)),
    ]);
    const result = resultXml('/chain.xml#STEP0', await stepDigest(s1, sOther, s1));
    await verifyHashChain(result, mapResolver({ 'message.xml': msg, 'chain.xml': chain, 'other.xml': other }), [
      '/message.xml',
    ]);
  });

  it('cycle → malformed_hash_chain', async () => {
    const chain = chainXml([step('A', stepRef('#B')), step('B', stepRef('#A'))]);
    const e = await fault(
      verifyHashChain(resultXml('/c.xml#A', new Uint8Array(64)), mapResolver({ 'c.xml': chain }), []),
    );
    expect(e.faultCode).toBe('malformed_hash_chain');
    expect(e.faultString).toBe('Cycle detected in hash chain at step: /c.xml#A');
  });

  it('depth > 64 → malformed_hash_chain', async () => {
    const steps = Array.from({ length: 70 }, (_, i) => step(`S${i}`, stepRef(`#S${i + 1}`)));
    steps.push(step('S70', hashValue(new Uint8Array(64))));
    const e = await fault(
      verifyHashChain(resultXml('/c.xml#S0', new Uint8Array(64)), mapResolver({ 'c.xml': chainXml(steps) }), []),
    );
    expect(e.faultString).toBe('Hash chain exceeds maximum depth of 64');
  });

  it('> 1024 distinct steps → malformed_hash_chain', async () => {
    // A wide tree: S0 refs 40 steps, each refs 30 leaves → 1 + 40 + 1200 steps, depth 3.
    const steps = [step('S0', ...Array.from({ length: 40 }, (_, i) => stepRef(`#M${i}`)))];
    for (let i = 0; i < 40; i++) {
      steps.push(step(`M${i}`, ...Array.from({ length: 30 }, (_, j) => stepRef(`#L${i}_${j}`))));
      for (let j = 0; j < 30; j++) steps.push(step(`L${i}_${j}`));
    }
    const e = await fault(
      verifyHashChain(resultXml('/c.xml#S0', new Uint8Array(64)), mapResolver({ 'c.xml': chainXml(steps) }), []),
    );
    expect(e.faultString).toBe('Hash chain exceeds maximum step count of 1024');
  });

  it('> 10000 values → malformed_hash_chain', async () => {
    const values = hashValue(new Uint8Array(1)).repeat(10_001);
    const e = await fault(
      verifyHashChain(
        resultXml('/c.xml#S0', new Uint8Array(64)),
        mapResolver({ 'c.xml': chainXml([step('S0', values)]) }),
        [],
      ),
    );
    expect(e.faultString).toBe('Hash chain exceeds maximum value count of 10000');
  });

  it('DataRef that should resolve but cannot → invalid_reference', async () => {
    const resolver: HashChainReferenceResolver = {
      shouldResolve: () => true,
      resolve: (uri) => (uri === '/c.xml' ? encodeUtf8(chainXml([step('S', dataRef('/gone', new Uint8Array(64)))])) : null),
    };
    const e = await fault(verifyHashChain(resultXml('/c.xml#S', new Uint8Array(64)), resolver, []));
    expect(e.faultCode).toBe('invalid_reference');
    expect(e.faultString).toBe('Cannot resolve URI: /gone');
  });

  it('a "#frag" result URI with no current chain → internal_error (Java NPE)', async () => {
    expect(await code(verifyHashChain(resultXml('#S', new Uint8Array(64)), mapResolver({}), []))).toBe(
      'internal_error',
    );
  });
});

describe('verifyTimestampHashChain', () => {
  async function tsContainer(signatures: string, tamper = false) {
    const sig = await h(signatures);
    const hv = await h('earlier');
    const chain = chainXml([step('STEP0', hashValue(hv), dataRef('/META-INF/signatures.xml', sig))]);
    const result = resultXml('/ts-hashchain.xml#STEP0', await stepDigest(hv, sig));
    return {
      result,
      container: fakeContainer({
        'META-INF/signatures.xml': tamper ? signatures + ' ' : signatures,
        'ts-hashchain.xml': chain,
        'ts-hashchainresult.xml': result,
      }),
    };
  }

  it('returns the UTF-8 bytes of ts-hashchainresult.xml on success', async () => {
    const { container, result } = await tsContainer('<sig/>');
    expect(await verifyTimestampHashChain(container)).toEqual(encodeUtf8(result));
  });

  it('returns null without a ts hash chain', async () => {
    expect(await verifyTimestampHashChain(fakeContainer({ 'message.xml': '<m/>' }))).toBeNull();
  });

  it('signatures.xml changed → plain malformed_signature', async () => {
    const { container } = await tsContainer('<sig/>', true);
    const e = await fault(verifyTimestampHashChain(container));
    expect(e.faultCode).toBe('malformed_signature');
    expect(e.faultString).toMatch(/^Failed to verify time-stamp hash chain: invalid_hash_chain_ref: /);
  });

  it('broken ts chain structure → plain malformed_signature', async () => {
    const { container } = await tsContainer('<sig/>');
    const c = fakeContainer({ ...Object.fromEntries(container.entries), 'ts-hashchain.xml': '<x/>' });
    expect(await code(verifyTimestampHashChain(c))).toBe('malformed_signature');
  });
});
