// Configuration anchor

import { decodeBase64Strict } from '../util/bytes';
import { GlobalConfError } from './errors';
import { childText, children, parseXml } from './xml';

export const XROAD_NS = 'http://x-road.eu/xsd/xroad.xsd';

export interface AnchorSource {
  downloadURL: string;
  /** DER bytes of each verification certificate. */
  verificationCerts: Uint8Array[];
}

export interface ConfigurationAnchor {
  instanceIdentifier: string;
  generatedAt?: string;
  sources: AnchorSource[];
}

const invalid = (msg: string) => new GlobalConfError('ANCHOR_INVALID', msg);

export function parseAnchor(xml: string): ConfigurationAnchor {
  const root = parseXml(xml, invalid);
  if (root.localName !== 'configurationAnchor' || root.namespaceURI !== XROAD_NS) {
    throw invalid(`unexpected root element {${root.namespaceURI ?? ''}}${root.localName}`);
  }
  const instanceIdentifier = childText(root, 'instanceIdentifier');
  if (!instanceIdentifier) throw invalid('instanceIdentifier missing');

  const sources = children(root, 'source').map((src, i): AnchorSource => {
    const downloadURL = childText(src, 'downloadURL');
    if (!downloadURL) throw invalid(`source[${i}]: downloadURL missing`);
    const verificationCerts = children(src, 'verificationCert').map((c, j) => {
      const der = decodeBase64Strict(c.textContent ?? '');
      if (!der || der.length === 0) throw invalid(`source[${i}].verificationCert[${j}]: bad base64`);
      return der;
    });
    if (verificationCerts.length === 0) throw invalid(`source[${i}]: no verificationCert`);
    return { downloadURL, verificationCerts };
  });
  if (sources.length === 0) throw invalid('no source');

  const generatedAt = childText(root, 'generatedAt');
  return { instanceIdentifier, sources, ...(generatedAt ? { generatedAt } : {}) };
}

/** All verification certs across all sources (any source may have signed the directory). */
export function anchorCerts(anchor: ConfigurationAnchor): Uint8Array[] {
  return anchor.sources.flatMap((s) => s.verificationCerts);
}
