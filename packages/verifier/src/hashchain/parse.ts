/**
 * Hash chain XML parsing: the port of HashChainVerifier.validateAndParse
 * (JAXB unmarshal with hashchain.xsd validation, HCV:231-253).
 *
 *   parseHashChainResult(xml) → HashChainResultModel
 *   parseHashChain(xml)       → HashChainModel
 *
 * The XSD is checked by hand: root element, child order and multiplicity,
 * required attributes, no unknown attributes, element-only content (whitespace
 * only between elements), base64Binary DigestValue, NCName and unique HashStep
 * ids.
 *
 * JAXB unmarshals by *declared type* and ignores the root element name, so a
 * schema-valid document whose root is the other global element is accepted
 * and mapped field by field (unknown content dropped). Parity:
 *   HashChain parsed as a result  → URI null (the verifier then fails with
 *                                   internal_error, Java NPE)
 *   HashChainResult parsed as a chain → a chain without steps
 *
 * Fault codes:
 *   malformed_hash_chain "Parsing hash chain failed" - not well-formed (incl.
 *     any DOCTYPE, which the port rejects outright) or not schema-valid.
 */
import { CodedError, ErrorCodes } from '../util/errors';
import { childElements, parseXml, type XElement } from '../xml/safe';

export const HASHCHAIN_NS = 'http://cyber.ee/hashchain';
export const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
const XSI_NS = 'http://www.w3.org/2001/XMLSchema-instance';
const XMLNS_NS = 'http://www.w3.org/2000/xmlns/';
const XML_NS = 'http://www.w3.org/XML/1998/namespace';

export interface HashValueModel {
  kind: 'HashValue';
  digestMethod?: string;
  hasTransforms: boolean;
  digestValue: Uint8Array;
}

export interface StepRefModel {
  kind: 'StepRef';
  uri: string;
  digestMethod?: string;
}

export interface DataRefModel {
  kind: 'DataRef';
  uri: string;
  digestMethod?: string;
  hasTransforms: boolean;
  digestValue: Uint8Array;
}

export type HashValueOrRef = HashValueModel | StepRefModel | DataRefModel;

export interface HashStepModel {
  id: string | null;
  values: HashValueOrRef[];
}

export interface HashChainModel {
  defaultDigestMethod?: string;
  steps: HashStepModel[];
}

export interface HashChainResultModel {
  /** null only when the document was a HashChain (JAXB declared-type quirk). */
  uri: string | null;
  digestMethod?: string;
  digestValue: Uint8Array | null;
}

class SchemaError extends Error {}

function fail(msg: string): never {
  throw new SchemaError(msg);
}

function malformed(cause: unknown): CodedError {
  return new CodedError(ErrorCodes.X_MALFORMED_HASH_CHAIN, 'Parsing hash chain failed', { cause });
}

function parseRoot(xml: string): XElement {
  try {
    return parseXml(xml, ErrorCodes.X_MALFORMED_HASH_CHAIN).documentElement as XElement;
  } catch (e) {
    throw malformed(e);
  }
}

export function parseHashChainResult(xml: string): HashChainResultModel {
  const root = parseRoot(xml);
  try {
    const ids = new Set<string>();
    if (isHc(root, 'HashChainResult')) return readResult(root);
    if (isHc(root, 'HashChain')) {
      readChain(root, ids);
      return { uri: null, digestValue: null };
    }
    fail(`Unexpected root element ${root.tagName}`);
  } catch (e) {
    if (e instanceof SchemaError) throw malformed(e);
    throw e;
  }
}

export function parseHashChain(xml: string): HashChainModel {
  const root = parseRoot(xml);
  try {
    if (isHc(root, 'HashChain')) return readChain(root, new Set());
    if (isHc(root, 'HashChainResult')) {
      readResult(root);
      return { steps: [] };
    }
    fail(`Unexpected root element ${root.tagName}`);
  } catch (e) {
    if (e instanceof SchemaError) throw malformed(e);
    throw e;
  }
}

function isHc(el: XElement, local: string): boolean {
  return el.namespaceURI === HASHCHAIN_NS && el.localName === local;
}

function isDs(el: XElement, local: string): boolean {
  return el.namespaceURI === DS_NS && el.localName === local;
}

/** Checks attributes against the allowed (no-namespace) names; returns their values. */
function attributes(el: XElement, allowed: readonly string[]): Map<string, string> {
  const out = new Map<string, string>();
  const attrs = el.attributes;
  for (let i = 0; i < attrs.length; i++) {
    const a = attrs.item(i)!;
    const ns = a.namespaceURI;
    if (ns === XMLNS_NS || a.name === 'xmlns' || a.name.startsWith('xmlns:')) continue;
    if (ns === XSI_NS || ns === XML_NS) continue;
    const local = a.localName ?? a.name;
    if (ns || !allowed.includes(local)) fail(`Attribute ${a.name} not allowed on ${el.tagName}`);
    out.set(local, a.value);
  }
  return out;
}

/** Element-only content: only whitespace text between child elements. */
function elementOnly(el: XElement): XElement[] {
  for (let n = el.firstChild; n; n = n.nextSibling) {
    if ((n.nodeType === 3 || n.nodeType === 4) && !/^[ \t\r\n]*$/.test((n as unknown as { data: string }).data)) {
      fail(`Text content not allowed in ${el.tagName}`);
    }
  }
  return childElements(el);
}

function requiredAttr(attrs: Map<string, string>, name: string, el: XElement): string {
  const v = attrs.get(name);
  if (v === undefined) fail(`Attribute ${name} is required on ${el.tagName}`);
  return v;
}

/** ds:DigestMethodType: Algorithm required; mixed content of ##other elements. */
function readDigestMethod(el: XElement): string {
  const algorithm = requiredAttr(attributes(el, ['Algorithm']), 'Algorithm', el);
  for (const c of childElements(el)) {
    if (!c.namespaceURI || c.namespaceURI === DS_NS) fail(`Element ${c.tagName} not allowed in ${el.tagName}`);
  }
  return algorithm;
}

/** ds:Transforms: one or more ds:Transform with a required Algorithm. */
function readTransforms(el: XElement): void {
  attributes(el, []);
  const kids = elementOnly(el);
  if (kids.length === 0) fail('ds:Transforms requires at least one ds:Transform');
  for (const t of kids) {
    if (!isDs(t, 'Transform')) fail(`Element ${t.tagName} not allowed in ds:Transforms`);
    requiredAttr(attributes(t, ['Algorithm']), 'Algorithm', t);
  }
}

/** ds:DigestValue: xs:base64Binary. */
function readDigestValue(el: XElement): Uint8Array {
  attributes(el, []);
  if (childElements(el).length > 0) fail('ds:DigestValue must not contain elements');
  const text = (el.textContent ?? '').replace(/[ \t\r\n]/g, '');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) {
    fail('ds:DigestValue is not valid base64Binary');
  }
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Sequential cursor over child elements, for xs:sequence checks. */
class Seq {
  private i = 0;
  constructor(
    private readonly parent: XElement,
    private readonly kids: XElement[],
  ) {}
  take(pred: (e: XElement) => boolean): XElement | undefined {
    const k = this.kids[this.i];
    if (k && pred(k)) {
      this.i++;
      return k;
    }
    return undefined;
  }
  need(pred: (e: XElement) => boolean, what: string): XElement {
    return this.take(pred) ?? fail(`Expected ${what} in ${this.parent.tagName}`);
  }
  end(): void {
    const k = this.kids[this.i];
    if (k) fail(`Unexpected element ${k.tagName} in ${this.parent.tagName}`);
  }
}

function readResult(el: XElement): HashChainResultModel {
  const uri = requiredAttr(attributes(el, ['URI']), 'URI', el);
  const seq = new Seq(el, elementOnly(el));
  const dm = seq.take((e) => isDs(e, 'DigestMethod'));
  const dv = seq.need((e) => isDs(e, 'DigestValue'), 'ds:DigestValue');
  seq.end();
  return { uri, digestMethod: dm ? readDigestMethod(dm) : undefined, digestValue: readDigestValue(dv) };
}

function readChain(el: XElement, ids: Set<string>): HashChainModel {
  attributes(el, []);
  const seq = new Seq(el, elementOnly(el));
  const ddm = seq.take((e) => isHc(e, 'DefaultDigestMethod'));
  const steps: HashStepModel[] = [];
  for (let s = seq.take((e) => isHc(e, 'HashStep')); s; s = seq.take((e) => isHc(e, 'HashStep'))) {
    steps.push(readStep(s, ids));
  }
  seq.end();
  return { defaultDigestMethod: ddm ? readDigestMethod(ddm) : undefined, steps };
}

const NCNAME = /^[A-Za-z_À-￿][A-Za-z0-9._\-·À-￿]*$/;

function readStep(el: XElement, ids: Set<string>): HashStepModel {
  const raw = attributes(el, ['id']).get('id');
  let id: string | null = null;
  if (raw !== undefined) {
    id = raw.replace(/[ \t\r\n]+/g, ' ').trim(); // xs:ID whitespace collapse
    if (!NCNAME.test(id)) fail(`Invalid id "${raw}"`);
    if (ids.has(id)) fail(`Duplicate id "${id}"`);
    ids.add(id);
  }
  const values: HashValueOrRef[] = [];
  for (const c of elementOnly(el)) {
    if (isHc(c, 'HashValue')) values.push(readHashValue(c));
    else if (isHc(c, 'StepRef')) values.push(readStepRef(c));
    else if (isHc(c, 'DataRef')) values.push(readDataRef(c));
    else fail(`Element ${c.tagName} not allowed in HashStep`);
  }
  return { id, values };
}

function readHashValue(el: XElement): HashValueModel {
  attributes(el, []);
  const seq = new Seq(el, elementOnly(el));
  const dm = seq.take((e) => isDs(e, 'DigestMethod'));
  const tr = seq.take((e) => isDs(e, 'Transforms'));
  const dv = seq.need((e) => isDs(e, 'DigestValue'), 'ds:DigestValue');
  seq.end();
  if (tr) readTransforms(tr);
  return {
    kind: 'HashValue',
    digestMethod: dm ? readDigestMethod(dm) : undefined,
    hasTransforms: !!tr,
    digestValue: readDigestValue(dv),
  };
}

function readStepRef(el: XElement): StepRefModel {
  const uri = requiredAttr(attributes(el, ['URI']), 'URI', el);
  const seq = new Seq(el, elementOnly(el));
  const dm = seq.take((e) => isDs(e, 'DigestMethod'));
  seq.end();
  return { kind: 'StepRef', uri, digestMethod: dm ? readDigestMethod(dm) : undefined };
}

function readDataRef(el: XElement): DataRefModel {
  const uri = requiredAttr(attributes(el, ['URI']), 'URI', el);
  const seq = new Seq(el, elementOnly(el));
  const dm = seq.take((e) => isDs(e, 'DigestMethod'));
  const tr = seq.take((e) => isDs(e, 'Transforms'));
  const dv = seq.need((e) => isDs(e, 'DigestValue'), 'ds:DigestValue');
  seq.end();
  if (tr) readTransforms(tr);
  return {
    kind: 'DataRef',
    uri,
    digestMethod: dm ? readDigestMethod(dm) : undefined,
    hasTransforms: !!tr,
    digestValue: readDigestValue(dv),
  };
}
