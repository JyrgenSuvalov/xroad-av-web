// shared-params.xml (V6 primary, V2–V5 tolerated)
// Only what the verifier needs is modelled, plus members for display.

import { decodeCertField } from './crypto';
import { GlobalConfError } from './errors';
import { XROAD_NS } from './anchor';
import { type XmlElement, child, childText, children, parseXml } from './xml';

export interface OcspInfo {
  url: string;
  /** DER of the responder certificate, when published. */
  cert?: Uint8Array;
}

export interface CaInfo {
  /** DER of the CA certificate. */
  cert: Uint8Array;
  ocsp: OcspInfo[];
}

export interface SharedParamsCa {
  name: string;
  authenticationOnly: boolean;
  topCA: CaInfo;
  intermediateCAs: CaInfo[];
  /** Java FQCN of the certificate profile, e.g. ee.ria.xroad.common.certificateprofile.impl.BasicCertificateProfileInfoProvider */
  certificateProfileInfo: string;
}

export interface SharedParamsTsa {
  name: string;
  url: string;
  cert: Uint8Array;
}

export interface Member {
  memberClass: string;
  memberCode: string;
  name: string;
  subsystems: { subsystemCode: string; subsystemName?: string }[];
}

export interface SharedParams {
  instanceIdentifier: string;
  approvedCAs: SharedParamsCa[];
  approvedTSAs: SharedParamsTsa[];
  members: Member[];
  globalSettings: {
    ocspFreshnessSeconds: number;
    memberClasses: { code: string; description?: string }[];
  };
}

const invalid = (msg: string) => new GlobalConfError('SHARED_PARAMS_INVALID', msg);

function req(el: XmlElement, name: string, where: string): string {
  const v = childText(el, name);
  if (v === undefined || v === '') throw invalid(`${where}/${name} missing`);
  return v;
}

function reqChild(el: XmlElement, name: string, where: string): XmlElement {
  const c = child(el, name);
  if (!c) throw invalid(`${where}/${name} missing`);
  return c;
}

function cert(el: XmlElement, where: string): Uint8Array {
  return decodeCertField(req(el, 'cert', where), (m) => invalid(`${where}/cert: ${m}`)).der;
}

function caInfo(el: XmlElement, where: string): CaInfo {
  return {
    cert: cert(el, where),
    ocsp: children(el, 'ocsp').map((o, i) => {
      const w = `${where}/ocsp[${i}]`;
      const certEl = child(o, 'cert');
      return {
        url: req(o, 'url', w),
        ...(certEl ? { cert: cert(o, w) } : {}),
      };
    }),
  };
}

/**
 * Parse shared-params XML. The element structure the verifier reads is the
 * same in V2..V6 (differences are in parts we ignore), so one parser
 * serves all versions.
 */
export function parseSharedParams(xml: string | Uint8Array): SharedParams {
  const text = typeof xml === 'string' ? xml : new TextDecoder('utf-8').decode(xml);
  const root = parseXml(text, invalid);
  if (root.localName !== 'conf' || root.namespaceURI !== XROAD_NS) {
    throw invalid(`unexpected root element {${root.namespaceURI ?? ''}}${root.localName}`);
  }
  const instanceIdentifier = req(root, 'instanceIdentifier', 'conf');

  const approvedCAs = children(root, 'approvedCA').map((ca, i): SharedParamsCa => {
    const w = `approvedCA[${i}]`;
    return {
      name: req(ca, 'name', w),
      authenticationOnly: childText(ca, 'authenticationOnly') === 'true',
      topCA: caInfo(reqChild(ca, 'topCA', w), `${w}/topCA`),
      intermediateCAs: children(ca, 'intermediateCA').map((ic, j) => caInfo(ic, `${w}/intermediateCA[${j}]`)),
      certificateProfileInfo: req(ca, 'certificateProfileInfo', w),
    };
  });

  const approvedTSAs = children(root, 'approvedTSA').map((t, i): SharedParamsTsa => {
    const w = `approvedTSA[${i}]`;
    return { name: req(t, 'name', w), url: req(t, 'url', w), cert: cert(t, w) };
  });

  const members = children(root, 'member').map((m, i): Member => {
    const w = `member[${i}]`;
    return {
      memberClass: req(reqChild(m, 'memberClass', w), 'code', `${w}/memberClass`),
      memberCode: req(m, 'memberCode', w),
      name: childText(m, 'name') ?? '',
      subsystems: children(m, 'subsystem').map((s, j) => {
        const subsystemName = childText(s, 'subsystemName');
        return {
          subsystemCode: req(s, 'subsystemCode', `${w}/subsystem[${j}]`),
          ...(subsystemName ? { subsystemName } : {}),
        };
      }),
    };
  });

  const gs = reqChild(root, 'globalSettings', 'conf');
  const freshness = req(gs, 'ocspFreshnessSeconds', 'conf/globalSettings');
  if (!/^-?\d+$/.test(freshness)) throw invalid(`ocspFreshnessSeconds ${JSON.stringify(freshness)}`);
  const memberClasses = children(gs, 'memberClass').map((mc, i) => {
    const description = childText(mc, 'description');
    return { code: req(mc, 'code', `globalSettings/memberClass[${i}]`), ...(description ? { description } : {}) };
  });

  return {
    instanceIdentifier,
    approvedCAs,
    approvedTSAs,
    members,
    globalSettings: { ocspFreshnessSeconds: Number(freshness), memberClasses },
  };
}

/** `nextupdate-params.xml` → `<conf><verifyNextUpdate>`; absent means true. */
export function parseNextUpdateParams(xml: string | Uint8Array): boolean {
  const text = typeof xml === 'string' ? xml : new TextDecoder('utf-8').decode(xml);
  const root = parseXml(text, invalid);
  const v = childText(root, 'verifyNextUpdate');
  return v === undefined ? true : v.toLowerCase() === 'true';
}
