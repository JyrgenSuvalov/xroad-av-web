// Unit tests per SANTUARIO-RULES.md rule: construction (model.ts), lazy References,
// Java MIME base64, KeyInfo resolution (cert.ts) and checkSignatureValue (signature-value.ts).
import { beforeAll, describe, expect, it } from 'vitest';
import { C14N_10 } from '../../src/c14n/c14n';
import type { AsicContainer } from '../../src/container/read';
import { DIGEST_URIS } from '../../src/hashchain/digest';
import { CodedError } from '../../src/util/errors';
import { parseXml } from '../../src/xml/safe';
import {
  checkRequiredReferences,
  decodeDsBase64,
  dsText,
  getSignatureValueBytes,
  getSigningCertificate,
  readSignatureModel,
  referenceAt,
  verifySignatureValue,
} from '../../src/xades';
import { keyUsage, makeCert, OID, rsaKey } from '../certpath/helpers';
import { fakeContainer } from '../hashchain/helpers';
import {
  b64,
  digestOfId,
  ECDSA_SHA256,
  load,
  makeKey,
  ref,
  sha512,
  sign,
  signatureXml,
  SIGNED_PROPERTIES,
  type TestKey,
} from './helpers';

const MESSAGE = '<message>hello</message>';
const container = () => fakeContainer({ 'message.xml': MESSAGE });

/** The fault code thrown by fn (sync or async), or 'ok'. */
async function code(fn: () => unknown): Promise<string> {
  try {
    await fn();
    return 'ok';
  } catch (e) {
    if (e instanceof CodedError) return e.faultCode;
    throw e;
  }
}

const bytes = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const text = (b: Uint8Array) => String.fromCharCode(...b);

describe('decodeDsBase64 (java.util.Base64 MIME decoder)', () => {
  it.each([
    ['QUJD', 'ABC'],
    ['QU\r\nJD', 'ABC'],
    ['Q*U!J D', 'ABC'],
    ['QUI', 'AB'],
    ['QQ', 'A'],
    ['QUI=', 'AB'],
    ['QQ==', 'A'],
    ['QQ==\n', 'A'],
    ['QQ==== ', 'A'],
    ['', ''],
    ['QUJDéü', 'ABC'],
  ])('%j → %j', (input, out) => {
    expect(text(decodeDsBase64(input))).toBe(out);
  });

  it.each(['Q', 'QUJDR', 'AAAA=', '=', 'QQ=A', 'QQ= =', 'QQ==A', 'Q=', 'QUI=A'])('%j → internal_error', async (input) => {
    expect(await code(() => decodeDsBase64(input))).toBe('internal_error');
  });

  it('dsText takes direct Text children only (not CDATA or nested elements)', () => {
    const el = parseXml('<a>QU<![CDATA[xx]]>JD<b>zz</b></a>').documentElement!;
    expect(dsText(el)).toBe('QUJD');
  });
});

describe('construction (new XMLSignature)', () => {
  const ok = ref('/message.xml', 'AAAA');
  const xml = (o: Partial<Parameters<typeof signatureXml>[0]> = {}) => signatureXml({ refs: [ok], ...o });

  it('accepts the minimal shape and does not touch References, c14n or SignatureValue', async () => {
    const broken = ref('/x', '', { body: '<ds:Foo/>' });
    const doc = xml({ refs: [broken], c14n: 'urn:unknown', signatureValue: 'Q' });
    expect(await code(() => load(doc))).toBe('ok');
  });

  it('ds:Signature in another namespace → malformed_signature', async () => {
    const doc = xml().replace('xmlns:ds="http://www.w3.org/2000/09/xmldsig#"', 'xmlns:ds="urn:other"');
    const el = parseXml(doc).getElementsByTagName('ds:Signature').item(0)!;
    expect(await code(() => readSignatureModel(el))).toBe('malformed_signature');
  });

  it.each([
    ['first child not SignedInfo', (s: string) => s.replace('<ds:SignedInfo>', '<ds:Foo/><ds:SignedInfo>')],
    ['no CanonicalizationMethod', (s: string) => s.replace(/<ds:CanonicalizationMethod[^>]*>/, '')],
    ['no SignatureMethod', (s: string) => s.replace(/<ds:SignatureMethod[^>]*>/, '')],
    ['SignatureMethod before CanonicalizationMethod', (s: string) =>
      s.replace(/(<ds:CanonicalizationMethod[^>]*>)(<ds:SignatureMethod[^>]*>)/, '$2$1')],
    ['unknown SignatureMethod', (s: string) => s.replace(/xmldsig-more#rsa-sha512/, 'xmldsig-more#rsa-foo')],
    ['no SignatureValue', (s: string) => s.replace(/<ds:SignatureValue>.*?<\/ds:SignatureValue>/, '')],
    ['foreign element after SignatureValue', (s: string) => s.replace('</ds:SignatureValue>', '</ds:SignatureValue><x/>')],
    ['KeyInfo after Object', (s: string) => s.replace('</ds:Object>', '</ds:Object><ds:KeyInfo/>')],
    ['second KeyInfo', (s: string) => s.replace('</ds:SignatureValue>', '</ds:SignatureValue><ds:KeyInfo/><ds:KeyInfo/>')],
  ])('%s → malformed_signature', async (_, edit) => {
    expect(await code(() => load(edit(xml())))).toBe('malformed_signature');
  });

  it.each([
    ['no Reference', xml({ refs: [] })],
    ['no Reference, even without CanonicalizationMethod (Manifest ctor runs first)',
      xml({ refs: [] }).replace(/<ds:CanonicalizationMethod[^>]*>/, '')],
    ['31 References', xml({ refs: Array(31).fill(ok) })],
    ['rsa-md5', xml({ signatureMethod: 'http://www.w3.org/2001/04/xmldsig-more#rsa-md5' })],
    ['ds:Object/Manifest without Reference', xml({ objects: '<ds:Object><ds:Manifest/></ds:Object>' })],
    ['ds:Object/*:Manifest (any namespace) with 31 References',
      xml({ objects: `<ds:Object><m:Manifest xmlns:m="urn:m">${Array(31).fill(ok).join('')}</m:Manifest></ds:Object>` })],
  ])('%s → internal_error', async (_, doc) => {
    expect(await code(() => load(doc))).toBe('internal_error');
  });

  it('30 References are allowed; KeyInfo then several Objects are allowed', async () => {
    expect(await code(() => load(xml({ refs: Array(30).fill(ok) })))).toBe('ok');
    const doc = xml({ keyInfo: '<ds:KeyInfo/>', objects: SIGNED_PROPERTIES + '<ds:Object/>' });
    expect(await code(() => load(doc))).toBe('ok');
  });
});

describe('Reference construction (SignedInfo.item, lazy)', () => {
  const broken = (body: string) => ref('/x', '', { body });
  const modelOf = (refs: string[]) => readSignatureModel(load(signatureXml({ refs })).signature);

  it.each([
    ['no DigestMethod', '<ds:DigestValue>AAAA</ds:DigestValue>'],
    ['no DigestValue', `<ds:DigestMethod Algorithm="${DIGEST_URIS.SHA512}"/>`],
    ['DigestValue before DigestMethod', `<ds:DigestValue/><ds:DigestMethod Algorithm="${DIGEST_URIS.SHA512}"/>`],
    ['empty Transforms', `<ds:Transforms/><ds:DigestMethod Algorithm="x"/><ds:DigestValue/>`],
    ['6 Transforms', `<ds:Transforms>${'<ds:Transform Algorithm="x"/>'.repeat(6)}</ds:Transforms><ds:DigestMethod Algorithm="x"/><ds:DigestValue/>`],
  ])('%s → internal_error', async (_, body) => {
    expect(await code(() => referenceAt(modelOf([broken(body)]), 0))).toBe('internal_error');
  });

  it('references(uri) stops at the first match, so a later broken Reference is not built', async () => {
    const m = modelOf([ref('/message.xml', 'AAAA'), broken('<ds:Foo/>')]);
    expect(await code(() => checkRequiredReferences(m))).toBe('ok');
    const m2 = modelOf([broken('<ds:Foo/>'), ref('/message.xml', 'AAAA')]);
    expect(await code(() => checkRequiredReferences(m2))).toBe('internal_error');
  });

  it('no required reference → malformed_signature', async () => {
    expect(await code(() => checkRequiredReferences(modelOf([ref('/nope.xml', 'AAAA')])))).toBe('malformed_signature');
  });
});

describe('signing certificate (KeyInfo.getX509Certificate + isSigningCert)', () => {
  let signerB64 = '';
  let caB64 = '';
  beforeAll(async () => {
    const caKey = await rsaKey();
    const ca = await makeCert({ subject: [[[OID.CN, 'Test CA']]], key: caKey, extensions: [keyUsage([5])] });
    const signer = await makeCert({
      subject: [[[OID.CN, 'Test signer']]],
      issuer: [[[OID.CN, 'Test CA']]],
      key: await rsaKey(),
      signer: caKey,
      extensions: [keyUsage([1])],
    });
    [caB64, signerB64] = [b64(ca.der), b64(signer.der)];
  });
  const certOf = (keyInfo: string | undefined) =>
    getSigningCertificate(readSignatureModel(load(signatureXml({ refs: [ref('/message.xml', 'AAAA')], keyInfo })).signature));
  const x509 = (c: string) => `<ds:X509Certificate>${c}</ds:X509Certificate>`;

  it('no KeyInfo → internal_error (NPE); no certificate → malformed_signature', async () => {
    expect(await code(() => certOf(undefined))).toBe('internal_error');
    expect(await code(() => certOf('<ds:KeyInfo><ds:KeyName>x</ds:KeyName></ds:KeyInfo>'))).toBe('malformed_signature');
  });

  it('the first X509Data that has a certificate wins; nested X509Data is searched', async () => {
    const a = certOf(`<ds:KeyInfo><ds:X509Data><ds:X509SubjectName>x</ds:X509SubjectName></ds:X509Data><ds:X509Data>${x509(signerB64)}</ds:X509Data></ds:KeyInfo>`);
    expect(a.der.length).toBeGreaterThan(500);
    const b = certOf(`<ds:KeyInfo><ds:X509Data><ds:X509Data>${x509(signerB64)}</ds:X509Data></ds:X509Data></ds:KeyInfo>`);
    expect(b.der).toEqual(a.der);
  });

  it('trailing bytes after the DER are ignored', async () => {
    const der = decodeDsBase64(signerB64);
    const padded = new Uint8Array([...der, 1, 2, 3]);
    expect(certOf(`<ds:KeyInfo><ds:X509Data>${x509(b64(padded))}</ds:X509Data></ds:KeyInfo>`).der).toEqual(der);
  });

  it('a broken first certificate → internal_error (later ones are not tried); bad padding → internal_error', async () => {
    const ki = `<ds:KeyInfo><ds:X509Data>${x509('AAAA')}${x509(signerB64)}</ds:X509Data></ds:KeyInfo>`;
    expect(await code(() => certOf(ki))).toBe('internal_error');
    expect(await code(() => certOf(`<ds:KeyInfo><ds:X509Data>${x509('AAAA=')}</ds:X509Data></ds:KeyInfo>`)))
      .toBe('internal_error');
  });

  it('a certificate without nonRepudiation (the CA) → malformed_signature', async () => {
    const ki = `<ds:KeyInfo><ds:X509Data>${x509(caB64)}${x509(signerB64)}</ds:X509Data></ds:KeyInfo>`;
    expect(await code(() => certOf(ki))).toBe('malformed_signature');
  });
});

describe('verifySignatureValue (checkSignatureValue)', () => {
  let rsa: TestKey;
  let ec: TestKey;
  let msgDigest: Uint8Array;
  beforeAll(async () => {
    [rsa, ec] = await Promise.all([makeKey('RSA'), makeKey('EC')]);
    msgDigest = await sha512(MESSAGE);
  });

  async function verify(refs: string[], o: { key?: TestKey; edit?: (s: string) => string; c?: AsicContainer } = {}) {
    const key = o.key ?? rsa;
    let xml = signatureXml({ refs, signatureMethod: key.alg === 'EC' ? ECDSA_SHA256 : undefined });
    if (refs.some((r) => r.includes('"#signed-properties"'))) {
      xml = xml.replace('__SP__', b64(await digestOfId(xml, 'signed-properties')));
    }
    xml = await sign(xml, key);
    if (o.edit) xml = o.edit(xml);
    return code(() => verifySignatureValue(load(xml), o.c ?? container(), key.signing));
  }
  const spRef = () => ref('#signed-properties', '__SP__');

  it('valid: /message.xml (raw bytes) and #signed-properties (C14N subtree)', async () => {
    expect(await verify([ref('/message.xml', msgDigest), spRef()])).toBe('ok');
  });

  it('ECDSA P-256 (raw r‖s) verifies', async () => {
    expect(await verify([ref('/message.xml', msgDigest)], { key: ec })).toBe('ok');
  });

  it('SignedInfo changed after signing → invalid_signature_value', async () => {
    const edit = (s: string) => s.replace('URI="/message.xml"', 'URI="/message.xml" Id="x"');
    expect(await verify([ref('/message.xml', msgDigest)], { edit })).toBe('invalid_signature_value');
  });

  it('invalid signature → invalid_signature_value without resolving references', async () => {
    const edit = (s: string) => s.replace(/<ds:SignatureValue>(.)/, (_, c) => `<ds:SignatureValue>${c === 'A' ? 'B' : 'A'}`);
    expect(await verify([ref('/unresolvable', 'AAAA'), ref(null, 'AAAA')], { edit })).toBe('invalid_signature_value');
  });

  it('digest mismatch → invalid_signature_value; a later failing reference is still resolved', async () => {
    expect(await verify([ref('/message.xml', 'AAAA')])).toBe('invalid_signature_value');
    expect(await verify([ref('/message.xml', 'AAAA'), ref('/unresolvable', 'AAAA')])).toBe('internal_error');
  });

  it.each([
    ['Reference without URI', ref(null, 'AAAA')],
    ['#id that does not exist', ref('#nope', 'AAAA')],
    ['unresolvable URI', ref('/nope.xml', 'AAAA')],
    ['attachment URI without a container digest', ref('/attachment9', 'AAAA')],
    ['MD5 DigestMethod', ref('/message.xml', 'AAAA', { digestMethod: DIGEST_URIS.MD5 })],
    ['unknown DigestMethod', ref('/message.xml', 'AAAA', { digestMethod: 'urn:x' })],
    ['DigestValue with bad padding', ref('/message.xml', 'AAAA=')],
    ['Transforms', ref('/message.xml', 'AAAA', { transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'] })],
    ['Reference without DigestMethod', ref('/message.xml', '', { body: '<ds:DigestValue>AAAA</ds:DigestValue>' })],
  ])('%s → internal_error', async (_, r) => {
    expect(await verify([ref('/message.xml', msgDigest), r])).toBe('internal_error');
  });

  it('attachments: precomputed digest compared as bytes, DigestMethod ignored', async () => {
    const att = new Uint8Array([1, 2, 3]);
    const d = await sha512(att);
    const c = fakeContainer({ 'message.xml': MESSAGE }, { attachment1: att }, { attachment1: d });
    const r = (dv: Uint8Array | string) => ref('/attachment1', dv, { digestMethod: DIGEST_URIS.MD5 });
    expect(await verify([ref('/message.xml', msgDigest), r(d)], { c })).toBe('ok');
    expect(await verify([ref('/message.xml', msgDigest), r(new Uint8Array(64))], { c })).toBe('invalid_signature_value');
  });

  it('URI="" resolves to the whole document', async () => {
    expect(await verify([ref('/message.xml', msgDigest), ref('', 'AAAA')])).toBe('invalid_signature_value');
  });

  it('unsupported CanonicalizationMethod → internal_error at verify time', async () => {
    const edit = (s: string) => s.replace(C14N_10, 'http://www.w3.org/2001/10/xml-exc-c14n#');
    expect(await verify([ref('/message.xml', msgDigest)], { edit })).toBe('internal_error');
  });

  it('SignatureValue: bad padding or wrong length → internal_error; whitespace is ignored', async () => {
    const pad = (s: string) => s.replace('</ds:SignatureValue>', '=A</ds:SignatureValue>');
    expect(await verify([ref('/message.xml', msgDigest)], { edit: pad })).toBe('internal_error');
    const short = (s: string) => s.replace(/<ds:SignatureValue>..../, '<ds:SignatureValue>');
    expect(await verify([ref('/message.xml', msgDigest)], { edit: short })).toBe('internal_error');
    const ws = (s: string) => s.replace(/<ds:SignatureValue>(.{10})/, '<ds:SignatureValue>$1 \r\n&#13;\t');
    expect(await verify([ref('/message.xml', msgDigest)], { edit: ws })).toBe('ok');
  });

  it('a key that does not fit the SignatureMethod → internal_error', async () => {
    const xml = await sign(signatureXml({ refs: [ref('/message.xml', msgDigest)] }), rsa);
    expect(await code(() => verifySignatureValue(load(xml), container(), ec.signing))).toBe('internal_error');
  });

  it('getSignatureValueBytes decodes leniently', () => {
    const xml = signatureXml({ refs: [ref('/message.xml', 'AAAA')], signatureValue: 'QU\r\nJD' });
    expect(text(getSignatureValueBytes(load(xml)))).toBe('ABC');
    expect(bytes('ABC')).toEqual(getSignatureValueBytes(load(xml)));
  });
});
