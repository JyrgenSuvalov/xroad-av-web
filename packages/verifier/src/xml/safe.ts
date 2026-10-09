/**
 * Safe XML parsing.
 *
 *   parseXml(text, errorCode = 'invalid_xml') → Document
 *     - namespace-aware (@xmldom/xmldom)
 *     - any DOCTYPE is rejected → no DTD and no entity declarations, so no
 *       entity expansion beyond the five predefined entities
 *     - comment nodes removed (Java setIgnoringComments(true)); adjacent text
 *       nodes merged as Xerces would produce them
 *     - XML 1.0 line-ending normalisation only (\r\n and \r → \n);
 *       xmldom's default also rewrites U+0085/U+2028/U+2029, which Java does not
 *     - every xmldom warning/error is fatal → CodedError(errorCode, message)
 *   firstElementByTagName(doc, qname) - DOM getElementsByTagName(qname)[0] (literal qualified-name match)
 *   childElements(el), textContent(node)
 */
import {
  DOMParser,
  type Comment,
  type Document,
  type Element,
  type Node,
  type ProcessingInstruction,
  type Text,
} from '@xmldom/xmldom';
import { CodedError, ErrorCodes } from '../util/errors';

export type XDocument = Document;
export type XElement = Element;
export type XNode = Node;
export type XText = Text;
export type XComment = Comment;
export type XProcessingInstruction = ProcessingInstruction;

const ELEMENT = 1;
const TEXT = 3;
const CDATA = 4;
const COMMENT = 8;
const DOCTYPE = 10;

export function parseXml(text: string, errorCode: string = ErrorCodes.X_INVALID_XML): XDocument {
  // xmldom 0.9 never expands entities declared in an internal subset (only
  // the predefined five); the DOCTYPE node itself is rejected below.
  const parser = new DOMParser({
    normalizeLineEndings: (s: string) => s.replace(/\r\n?/g, '\n'),
    onError: (level: string, message: string) => {
      throw new CodedError(errorCode, `${level}: ${message}`);
    },
  });
  let doc: XDocument;
  try {
    doc = parser.parseFromString(text, 'text/xml') ;
  } catch (e) {
    if (e instanceof CodedError) throw e;
    throw new CodedError(errorCode, e instanceof Error ? e.message : String(e), { cause: e });
  }
  if (!doc || !doc.documentElement) throw new CodedError(errorCode, 'No root element');
  for (let n = doc.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === DOCTYPE) throw new CodedError(errorCode, 'DOCTYPE is disallowed');
  }
  stripComments(doc);
  return doc;
}

function stripComments(node: XNode): void {
  let child = node.firstChild;
  while (child) {
    const next: XNode | null = child.nextSibling;
    if (child.nodeType === COMMENT) {
      const prev = child.previousSibling;
      node.removeChild(child);
      if (prev && next && prev.nodeType === TEXT && next.nodeType === TEXT) {
        (prev as XText).appendData((next as XText).data);
        const after: XNode | null = next.nextSibling;
        node.removeChild(next);
        child = after;
        continue;
      }
    } else if (child.nodeType === ELEMENT) {
      stripComments(child);
    }
    child = next;
  }
}

export function firstElementByTagName(doc: XDocument | XElement, qname: string): XElement | null {
  const list = doc.getElementsByTagName(qname);
  return list.length > 0 ? (list.item(0) as XElement) : null;
}

export function childElements(el: XNode): XElement[] {
  const out: XElement[] = [];
  for (let n = el.firstChild; n; n = n.nextSibling) if (n.nodeType === ELEMENT) out.push(n as XElement);
  return out;
}

/** Concatenated character data of the node's direct Text/CDATA children only. */
export function directText(el: XNode): string {
  let s = '';
  for (let n = el.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === TEXT || n.nodeType === CDATA) s += (n as XText).data;
  }
  return s;
}

/** DOM textContent (all descendant text). */
export function textContent(node: XNode): string {
  return node.textContent ?? '';
}
