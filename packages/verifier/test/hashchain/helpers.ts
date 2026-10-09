// Builders for hand-made hash chains and a minimal in-memory AsicContainer.
import type { AsicContainer } from '../../src/container/read';
import { stripSlash } from '../../src/container/read';
import { encodeBase64, encodeUtf8, sha512 } from '../../src/util/bytes';
import { encodeDigestList } from '../../src/hashchain/der';
import { DIGEST_URIS } from '../../src/hashchain/digest';

export const SHA512 = DIGEST_URIS.SHA512;
export const b64 = encodeBase64;

export function fakeContainer(
  entries: Record<string, string>,
  attachments: Record<string, Uint8Array> = {},
  attachmentDigests: Record<string, Uint8Array> = {},
): AsicContainer {
  const map = new Map(Object.entries(entries));
  return {
    entries: map,
    timestampTst: undefined,
    timestampValue: 'AAAA',
    timestampSource: 'embedded',
    timestampDer: new Uint8Array(),
    attachmentDigests: new Map(Object.entries(attachmentDigests)),
    attachments: new Map(Object.entries(attachments)),
    get: (n) => map.get(stripSlash(n)),
    getBytes: (n) => {
      const v = map.get(stripSlash(n));
      return v === undefined ? undefined : encodeUtf8(v);
    },
    hasEntry: (n) => map.has(stripSlash(n)) || stripSlash(n) in attachmentDigests,
  };
}

const HEAD =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
const NS = 'xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:ns2="http://cyber.ee/hashchain"';

export const dataRef = (uri: string, digest: Uint8Array) =>
  `<ns2:DataRef URI="${uri}"><DigestValue>${b64(digest)}</DigestValue></ns2:DataRef>`;
export const hashValue = (digest: Uint8Array) => `<ns2:HashValue><DigestValue>${b64(digest)}</DigestValue></ns2:HashValue>`;
export const stepRef = (uri: string) => `<ns2:StepRef URI="${uri}"/>`;
export const step = (id: string, ...values: string[]) => `<ns2:HashStep id="${id}">${values.join('')}</ns2:HashStep>`;

export function chainXml(steps: string[], defaultDigest: string | null = SHA512): string {
  const ddm = defaultDigest ? `<ns2:DefaultDigestMethod Algorithm="${defaultDigest}"/>` : '';
  return `${HEAD}<ns2:HashChain ${NS}>${ddm}${steps.join('')}</ns2:HashChain>`;
}

export function resultXml(uri: string, digest: Uint8Array, alg: string | null = SHA512): string {
  const dm = alg ? `<DigestMethod Algorithm="${alg}"/>` : '';
  return `${HEAD}<ns2:HashChainResult URI="${uri}" ${NS}>${dm}<DigestValue>${b64(digest)}</DigestValue></ns2:HashChainResult>`;
}

/** SHA-512 of the UTF-8 bytes of a string. */
export const h = (s: string | Uint8Array) => sha512(typeof s === 'string' ? encodeUtf8(s) : s);

/** SHA-512 over a step made of (sha512, digest) items: what a StepRef/result digests. */
export const stepDigest = (...digests: Uint8Array[]) =>
  sha512(encodeDigestList(digests.map((value) => ({ algorithm: SHA512, value }))));

/**
 * A valid batch container: message.xml + 2 attachments, a single-step
 * sig-hashchain (DataRef /message.xml, /attachment1, /attachment2) and the
 * matching result.
 */
export async function batchContainer(over: { message?: string; attachment1?: Uint8Array } = {}) {
  const message = '<Envelope>hello</Envelope>';
  const att1 = encodeUtf8('attachment one');
  const att2 = encodeUtf8('attachment two');
  const mDigest = await h(message);
  const a1 = await sha512(att1);
  const a2 = await sha512(att2);
  const chain = chainXml([
    step('STEP0', dataRef('/message.xml', mDigest), dataRef('/attachment1', a1), dataRef('/attachment2', a2)),
  ]);
  const result = resultXml('/sig-hashchain.xml#STEP0', await stepDigest(mDigest, a1, a2));
  const actualAtt1 = over.attachment1 ?? att1;
  const container = fakeContainer(
    {
      'message.xml': over.message ?? message,
      'sig-hashchain.xml': chain,
      'sig-hashchainresult.xml': result,
    },
    { attachment1: actualAtt1, attachment2: att2 },
    { attachment1: await sha512(actualAtt1), attachment2: a2 },
  );
  return { container, chain, result, mDigest, a1, a2 };
}
