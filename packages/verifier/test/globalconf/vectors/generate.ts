// Generates the globalconf test vectors.
//
//   node packages/verifier/test/globalconf/vectors/generate.ts
//
// Input: the X-Road 7.8.3 system-test fixture (instance DEV), copied into
// xroad-fixture/ when XROAD_SRC points at an X-Road 7.8.3 checkout, otherwise
// read from the committed copy. Uses a TEST signing key (test-signing-key.pem),
// created with openssl on first run and committed. Never a real key.
// RSASSA-PKCS1-v1_5 is deterministic, so re-running reproduces identical files.

import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const here = import.meta.dirname;
const out = here;
const xrOut = join(out, 'xroad-fixture');
const SP_DIR = 'V6/20251110170000548026000';

const keyPath = join(out, 'test-signing-key.pem');
const certPath = join(out, 'test-signing-cert.der');
if (!existsSync(keyPath) || !existsSync(certPath)) {
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha512',
    '-keyout', keyPath, '-subj', '/CN=testSigningKey',
    // Validity 1970..2038, so pinned test clocks fall inside it.
    '-not_before', '19700101000000Z', '-not_after', '20380101000000Z',
    '-outform', 'DER', '-out', certPath,
  ], { stdio: 'inherit' });
}
const testKey = createPrivateKey(readFileSync(keyPath));
const testCertDer = readFileSync(certPath);
const b64 = (b: Buffer) => b.toString('base64');
const sha512 = (b: Buffer | string) => createHash('sha512').update(b).digest();

// Base: X-Road 7.8.3 system-test fixture (MIT, © NIIS), instance DEV.
if (process.env.XROAD_SRC) {
  const xr = join(process.env.XROAD_SRC, 'src/security-server/system-test/src/intTest/resources');
  mkdirSync(join(xrOut, SP_DIR), { recursive: true });
  const pub = join(xr, 'nginx-container-files/var/lib/xroad/public/V6');
  copyFileSync(join(pub, 'internalconf'), join(xrOut, 'V6/internalconf'));
  copyFileSync(join(pub, '20251110170000548026000/shared-params.xml'), join(xrOut, SP_DIR, 'shared-params.xml'));
  copyFileSync(join(xr, 'files/trusted-anchor/configuration_anchor_CS_internal.xml'), join(xrOut, 'anchor.xml'));
  writeFileSync(
  join(xrOut, 'NOTICE.md'),
  'Copied from X-Road 7.8.3 (MIT License, Copyright (c) 2019- Nordic Institute for Interoperability Solutions (NIIS)),\n' +
    'src/security-server/system-test/src/intTest/resources/{nginx-container-files/var/lib/xroad/public/V6,files/trusted-anchor}.\n' +
    'Used unchanged as a cross-implementation test vector and as the base of the other globalconf test vectors.\n',
  );
}


// --- test anchor: fixture anchor with every verificationCert replaced -----------
const anchorXml = readFileSync(join(xrOut, 'anchor.xml'), 'utf8');
writeFileSync(
  join(out, 'test-anchor.xml'),
  anchorXml.replace(/<verificationCert>[^<]*<\/verificationCert>/g, `<verificationCert>${b64(testCertDer)}</verificationCert>`),
);

// --- re-sign tool -------------------------------------------------------------
interface Split {
  prefix: string; // outer header + first delimiter + part-1 headers + blank line
  inner: string; // signed bytes
  sigHeaders: string; // part-2 header block (without the trailing blank line)
  boundary: string;
}

function split(raw: string): Split {
  const boundary = /boundary=([^;\r\n]+)/.exec(raw.slice(0, raw.indexOf('\r\n')))![1]!;
  const firstDelim = raw.indexOf(`--${boundary}\r\n`);
  const innerStart = raw.indexOf('\r\n\r\n', firstDelim) + 4;
  const secondDelim = raw.indexOf(`\r\n--${boundary}\r\n`, innerStart);
  const sigHdrStart = secondDelim + `\r\n--${boundary}\r\n`.length;
  const sigHdrEnd = raw.indexOf('\r\n\r\n', sigHdrStart);
  return {
    prefix: raw.slice(0, innerStart),
    inner: raw.slice(innerStart, secondDelim),
    sigHeaders: raw.slice(sigHdrStart, sigHdrEnd),
    boundary,
  };
}

interface ResignOptions {
  edit?: (inner: string) => string;
  /** Keep the original Verification-certificate-hash (V5). */
  keepCertHash?: boolean;
  editSigHeaders?: (h: string) => string;
}

function resign(raw: string, o: ResignOptions = {}): string {
  const s = split(raw);
  const inner = o.edit ? o.edit(s.inner) : s.inner;
  const sig = sign('sha512', Buffer.from(inner, 'latin1'), testKey);
  let hdr = s.sigHeaders;
  if (!o.keepCertHash) {
    hdr = hdr.replace(/(Verification-certificate-hash: )[^;\r\n]+/, `$1${b64(sha512(testCertDer))}`);
  }
  if (o.editSigHeaders) hdr = o.editSigHeaders(hdr);
  const B = s.boundary;
  return `${s.prefix}${inner}\r\n--${B}\r\n${hdr}\r\n\r\n${b64(sig)}\r\n--${B}--\r\n`;
}

const v6 = readFileSync(join(xrOut, 'V6/internalconf'), 'latin1');
const sp = readFileSync(join(xrOut, SP_DIR, 'shared-params.xml'));
const setExpire = (d: string) => (inner: string) => inner.replace(/Expire-date: [^\r]+/, `Expire-date: ${d}`);
const sharedBlock = /(Content-identifier: SHARED-PARAMETERS[^\r]*\r\nContent-location: )([^\r]+)/;

const vectors: Record<string, string> = {
  // V9 baseline: unchanged content, signed by the test key (OK with test anchor).
  'resigned.internalconf': resign(v6),
  // V3 expired, re-signed variant.
  'expired-2020.internalconf': resign(v6, { edit: setExpire('2020-01-01T00:00:00Z') }),
  // V4 = resigned.internalconf with the fixture anchor. V5: hash header forged to the fixture anchor cert.
  'forged-hash.internalconf': resign(v6, { keepCertHash: true }),
  // V6 signed-bytes tamper (not re-signed): one byte of the Expire-date value.
  'tampered-expire.internalconf': v6.replace(/(Expire-date: \d{3})(\d)/, (_, a: string, d: string) => a + ((Number(d) + 1) % 10)),
  // V8 part-hash tamper, re-signed.
  'part-hash-resigned.internalconf': resign(v6, {
    edit: (inner) =>
      inner.replace(/(SHARED-PARAMETERS[\s\S]*?\r\n\r\n)([^\r]+)/, (_, h: string) => h + b64(sha512('not the shared params'))),
  }),
  // V10 instance mismatch.
  'instance-other.internalconf': resign(v6, {
    edit: (inner) => inner.replace(/SHARED-PARAMETERS; instance='[^']*'/, "SHARED-PARAMETERS; instance='other'"),
  }),
  // V11 malformed variants (re-signed so only the targeted defect fails).
  'no-expire.internalconf': resign(v6, { edit: (inner) => inner.replace(/Expire-date: [^\r]+\r\n/, '') }),
  'bad-expire.internalconf': resign(v6, { edit: setExpire('tomorrow') }),
  'cte-uppercase.internalconf': resign(v6, {
    edit: (inner) => inner.replace(
      /Content-transfer-encoding: base64(\r\nContent-identifier: SHARED)/,
      'Content-transfer-encoding: BASE64$1',
    ),
  }),
  'unknown-sigalg.internalconf': resign(v6, {
    editSigHeaders: (h) => h.replace(/Signature-Algorithm-Id: [^\r]+/, 'Signature-Algorithm-Id: http://example.com/rot13'),
  }),
  'two-shared.internalconf': resign(v6, {
    edit: (inner) => {
      const m = /--[^\r]+\r\nContent-type[^]*?SHARED-PARAMETERS[^]*?\r\n\r\n[^\r]+\r\n/.exec(inner)!;
      return inner.replace(m[0], m[0] + m[0]);
    },
  }),
  // V12 Content-location escapes.
  'location-evil-host.internalconf': resign(v6, { edit: (inner) => inner.replace(sharedBlock, '$1//evil.example/x.xml') }),
  'location-dotdot.internalconf': resign(v6, { edit: (inner) => inner.replace(sharedBlock, '$1/V6/../x.xml') }),
  // Version header that disagrees with ?version=6.
  'version-5.internalconf': resign(v6, { edit: (inner) => inner.replace('Version: 6', 'Version: 5') }),
  // V13 rollback: valid (test key) but older Expire-date than resigned.internalconf.
  'rollback.internalconf': resign(v6, {
    edit: (inner) => {
      const cur = /Expire-date: ([^\r]+)/.exec(inner)![1]!;
      return setExpire(new Date(Date.parse(cur) - 3600_000).toISOString().replace('.000Z', 'Z'))(inner);
    },
  }),
};
for (const [name, body] of Object.entries(vectors)) writeFileSync(join(out, name), body, 'latin1');

// V7: shared-params with one byte changed (directory unchanged).
const tampered = Buffer.from(sp);
const at = tampered.indexOf('ocspFreshnessSeconds>') + 'ocspFreshnessSeconds>'.length;
tampered[at] = tampered[at] === 0x39 ? 0x38 : tampered[at]! + 1;
writeFileSync(join(out, 'shared-params-tampered.xml'), tampered);

console.log(`wrote ${Object.keys(vectors).length + 2} vectors + test anchor to ${dirname(keyPath)}`);
