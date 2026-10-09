/**
 * Canonical XML 1.0 (inclusive), http://www.w3.org/TR/2001/REC-xml-c14n-20010315,
 * with or without comments.
 *
 *   canonicalize(node, { withComments? }) → Uint8Array (UTF-8)
 *     - node = Document: the whole document
 *     - node = Element: the document subset "this element and its descendants"
 *       (the XMLDSig same-document case, e.g. ds:SignedInfo). The apex element
 *       renders every namespace in scope and inherits xml:* attributes from
 *       its ancestors, as Santuario does.
 *   C14N_10, C14N_10_WITH_COMMENTS - algorithm URIs
 *
 * Comments are normally already removed by parseXml (Java ignores comments
 * while parsing).
 */
import { encodeUtf8 } from '../util/bytes';
import type { XComment, XElement, XNode, XProcessingInstruction, XText } from '../xml/safe';

export const C14N_10 = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
export const C14N_10_WITH_COMMENTS = `${C14N_10}#WithComments`;

const XMLNS_NS = 'http://www.w3.org/2000/xmlns/';
const XML_NS = 'http://www.w3.org/XML/1998/namespace';

type NsMap = Map<string, string>; // prefix ('' = default) → uri

export function canonicalize(node: XNode, opts: { withComments?: boolean } = {}): Uint8Array {
  return encodeUtf8(canonicalizeToString(node, opts));
}

export function canonicalizeToString(node: XNode, opts: { withComments?: boolean } = {}): string {
  const out: string[] = [];
  const withComments = opts.withComments ?? false;
  if (node.nodeType === 9) {
    // Document: PIs/comments outside the root are separated by #xA.
    let seenRoot = false;
    for (let n = node.firstChild; n; n = n.nextSibling) {
      if (n.nodeType === 1) {
        renderElement(n as XElement, new Map([['', '']]), out, withComments, null);
        seenRoot = true;
      } else if (n.nodeType === 7 || (n.nodeType === 8 && withComments)) {
        if (seenRoot) out.push('\n');
        out.push(n.nodeType === 7 ? pi(n as XProcessingInstruction) : `<!--${(n as XComment).data}-->`);
        if (!seenRoot) out.push('\n');
      }
    }
  } else if (node.nodeType === 1) {
    const el = node as XElement;
    renderElement(el, new Map([['', '']]), out, withComments, inheritedXmlAttrs(el));
  } else {
    throw new Error(`canonicalize: unsupported node type ${node.nodeType}`);
  }
  return out.join('');
}

/** xml:* attributes of ancestors (nearest wins), for a subtree apex. */
function inheritedXmlAttrs(el: XElement): Map<string, string> {
  const m = new Map<string, string>();
  for (let p = el.parentNode; p && p.nodeType === 1; p = p.parentNode) {
    const attrs = (p as XElement).attributes;
    for (let i = 0; i < attrs.length; i++) {
      const a = attrs.item(i)!;
      if (a.namespaceURI === XML_NS && !m.has((a.localName ?? a.name))) m.set((a.localName ?? a.name), a.value);
    }
  }
  return m;
}

/** All namespace bindings in scope at el (from el and its ancestors). */
function inScope(el: XElement): NsMap {
  const chain: XElement[] = [];
  for (let p: XNode | null = el; p && p.nodeType === 1; p = p.parentNode) chain.unshift(p as XElement);
  const m: NsMap = new Map();
  for (const e of chain) for (const [k, v] of declaredNs(e)) m.set(k, v);
  return m;
}

function declaredNs(el: XElement): [string, string][] {
  const res: [string, string][] = [];
  const attrs = el.attributes;
  for (let i = 0; i < attrs.length; i++) {
    const a = attrs.item(i)!;
    if (a.namespaceURI === XMLNS_NS || a.name === 'xmlns' || a.name.startsWith('xmlns:')) {
      res.push([a.name === 'xmlns' ? '' : a.name.slice(6), a.value]);
    }
  }
  return res;
}

function renderElement(
  el: XElement,
  rendered: NsMap,
  out: string[],
  withComments: boolean,
  apexXmlAttrs: Map<string, string> | null,
): void {
  const ns = apexXmlAttrs ? inScope(el) : null;
  const nsToRender: [string, string][] = [];
  const nextRendered: NsMap = new Map(rendered);
  const candidates = ns ? [...ns.entries()] : declaredNs(el);
  for (const [prefix, uri] of candidates) {
    if (prefix === 'xml') continue;
    if (ns && prefix === '' && uri === '') continue; // apex: empty default not rendered
    if ((rendered.get(prefix) ?? (prefix === '' ? '' : undefined)) === uri) continue;
    nsToRender.push([prefix, uri]);
    nextRendered.set(prefix, uri);
  }
  nsToRender.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  const attrs: { ns: string; local: string; name: string; value: string }[] = [];
  const own = el.attributes;
  const ownXml = new Set<string>();
  for (let i = 0; i < own.length; i++) {
    const a = own.item(i)!;
    if (a.namespaceURI === XMLNS_NS || a.name === 'xmlns' || a.name.startsWith('xmlns:')) continue;
    if (a.namespaceURI === XML_NS) ownXml.add(a.localName ?? a.name);
    attrs.push({ ns: a.namespaceURI ?? '', local: a.localName ?? a.name, name: a.name, value: a.value });
  }
  if (apexXmlAttrs) {
    for (const [local, value] of apexXmlAttrs) {
      if (!ownXml.has(local)) attrs.push({ ns: XML_NS, local, name: `xml:${local}`, value });
    }
  }
  attrs.sort((a, b) =>
    a.ns !== b.ns ? (a.ns < b.ns ? -1 : 1) : a.local < b.local ? -1 : a.local > b.local ? 1 : 0,
  );

  out.push('<', el.tagName);
  for (const [p, u] of nsToRender) out.push(p === '' ? ' xmlns="' : ` xmlns:${p}="`, escAttr(u), '"');
  for (const a of attrs) out.push(' ', a.name, '="', escAttr(a.value), '"');
  out.push('>');
  for (let n = el.firstChild; n; n = n.nextSibling) {
    switch (n.nodeType) {
      case 1:
        renderElement(n as XElement, nextRendered, out, withComments, null);
        break;
      case 3:
      case 4:
        out.push(escText((n as XText).data));
        break;
      case 7:
        out.push(pi(n as XProcessingInstruction));
        break;
      case 8:
        if (withComments) out.push(`<!--${(n as XComment).data}-->`);
        break;
      default:
        break;
    }
  }
  out.push('</', el.tagName, '>');
}

function pi(n: XProcessingInstruction): string {
  return n.data ? `<?${n.target} ${n.data}?>` : `<?${n.target}?>`;
}

function escText(s: string): string {
  return s.replace(/[&<>\r]/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&#xD;',
  );
}

function escAttr(s: string): string {
  return s.replace(/[&<"\t\n\r]/g, (c) =>
    c === '&'
      ? '&amp;'
      : c === '<'
        ? '&lt;'
        : c === '"'
          ? '&quot;'
          : c === '\t'
            ? '&#x9;'
            : c === '\n'
              ? '&#xA;'
              : '&#xD;',
  );
}
