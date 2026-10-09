// Hardened XML parsing for anchor / shared-params (DTD + entities disabled).
// xmldom never fetches external entities; we additionally refuse any DOCTYPE so
// internal entity expansion ("billion laughs") is impossible too.
//
// Deliberately separate from src/xml/safe.ts parseXml, which ports the Java
// message parser for fault-code parity: that one makes xmldom *warnings* fatal,
// strips comments and maps failures to CodedError. Global configuration is not
// part of the jar parity surface; here warnings are tolerated and failures are
// GlobalConfError (red/amber status). Sharing one parser would change which
// configurations are accepted.

import { DOMParser, type Element } from '@xmldom/xmldom';
import { childElements } from '../xml/safe';
import { GlobalConfError } from './errors';

export type XmlElement = Element;

export function parseXml(xml: string, onError: (msg: string) => GlobalConfError): XmlElement {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw onError('DOCTYPE/ENTITY declarations are not allowed');
  let doc;
  try {
    doc = new DOMParser({
      onError: (level, message) => {
        if (level !== 'warning') throw onError(`XML ${level}: ${message}`);
      },
    }).parseFromString(xml, 'text/xml');
  } catch (e) {
    if (e instanceof GlobalConfError) throw e;
    throw onError(`XML parse failed: ${String(e)}`);
  }
  const root = doc.documentElement;
  if (!root) throw onError('XML has no root element');
  return root;
}

/** Direct element children with the given local name and *no* namespace (X-Road children are unqualified). */
export function children(el: XmlElement, localName: string): XmlElement[] {
  return childElements(el).filter((c) => c.localName === localName && !c.namespaceURI);
}

export function child(el: XmlElement, localName: string): XmlElement | undefined {
  return children(el, localName)[0];
}

export function text(el: XmlElement | undefined): string | undefined {
  return el?.textContent?.trim();
}

export function childText(el: XmlElement, localName: string): string | undefined {
  return text(child(el, localName));
}
