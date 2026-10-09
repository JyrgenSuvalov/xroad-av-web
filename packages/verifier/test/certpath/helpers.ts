// Synthetic names/certificates for the binding/certpath/ocsp unit tests.
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { trustedCert } from '../../src/ocsp';
import type { TrustedCert } from '../../src/types';

export const OID = { CN: '2.5.4.3', O: '2.5.4.10', C: '2.5.4.6', SERIAL: '2.5.4.5', BC: '2.5.4.15' } as const;

type Ava = [oid: string, value: string] | [oid: string, value: string, kind: 'printable' | 'utf8'];

function avaValue(value: string, kind: 'printable' | 'utf8' = 'utf8') {
  return kind === 'printable' ? new asn1js.PrintableString({ value }) : new asn1js.Utf8String({ value });
}

/** Name DER in the given (DER) order; each inner array is one RDN (multi-valued if > 1). */
export function nameDer(rdns: Ava[][]): Uint8Array {
  const seq = new asn1js.Sequence({
    value: rdns.map(
      (avas) =>
        new asn1js.Set({
          value: avas.map(
            ([oid, value, kind]) =>
              new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: oid }), avaValue(value, kind)] }),
          ),
        }),
    ),
  });
  return new Uint8Array(seq.toBER());
}

export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export async function rsaKey(modulusLength = 2048): Promise<KeyPair> {
  return (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
}

export interface CertOpts {
  subject: Ava[][];
  issuer?: Ava[][];
  serial?: number;
  notBefore?: Date;
  notAfter?: Date;
  key: KeyPair;
  signer?: KeyPair;
  extensions?: pkijs.Extension[];
}

export async function makeCert(o: CertOpts): Promise<TrustedCert> {
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: o.serial ?? 1 });
  const subject = asn1js.fromBER(nameDer(o.subject).slice().buffer as ArrayBuffer).result;
  const issuer = asn1js.fromBER(nameDer(o.issuer ?? o.subject).slice().buffer as ArrayBuffer).result;
  cert.subject = new pkijs.RelativeDistinguishedNames({ schema: subject });
  cert.issuer = new pkijs.RelativeDistinguishedNames({ schema: issuer });
  cert.notBefore.value = o.notBefore ?? new Date('2026-01-01T00:00:00Z');
  cert.notAfter.value = o.notAfter ?? new Date('2036-01-01T00:00:00Z');
  if (o.extensions) cert.extensions = o.extensions;
  await cert.subjectPublicKeyInfo.importKey(o.key.publicKey);
  await cert.sign((o.signer ?? o.key).privateKey, 'SHA-256');
  const der = new Uint8Array(cert.toSchema(true).toBER());
  return trustedCert(der);
}

/** keyUsage extension with the given bits set (0 = digitalSignature, 1 = nonRepudiation, 5 = keyCertSign). */
export function keyUsage(bits: number[], critical = true): pkijs.Extension {
  const bytes = new Uint8Array(2);
  for (const b of bits) bytes[b >> 3]! |= 0x80 >> (b & 7);
  const used = bytes[1] ? 2 : 1;
  const bs = new asn1js.BitString({ valueHex: bytes.slice(0, used).buffer as ArrayBuffer, unusedBits: 0 });
  return new pkijs.Extension({ extnID: '2.5.29.15', critical, extnValue: bs.toBER() });
}

export function criticalExtension(oid: string): pkijs.Extension {
  return new pkijs.Extension({ extnID: oid, critical: true, extnValue: new asn1js.Null().toBER() });
}
