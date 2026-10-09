/**
 * Signature.getExtraCertificates (SIG:262-302): the certificates referenced
 * from xades:CompleteCertificateRefs/xades:CertRefs/xades:Cert under the first
 * ds:Object. Each Cert's URI names an element by `Id` anywhere in the document
 * (XmlUtils.getElementById: `//*[@Id = '<id without #>']`, first in document
 * order); its text is a base64 certificate whose digest must equal the Cert's
 * CertDigest. The certs are only validated, never used for the path (the trust
 * anchor is the signer cert's direct issuer).
 *
 *   getExtraCertificates(doc, object) → Uint8Array[] (DER)
 *     URI missing/empty           → malformed_signature "Missing certificate id attribute"
 *     no element with that Id     → malformed_signature "Could not find certificate with id <uri>"
 *     not a certificate           → malformed_signature
 *     digest mismatch             → malformed_signature "Certificate (<serial>) digest does not match"
 *     unexpected structure        → internal_error (Java ClassCastException / NPE)
 *
 * Real containers have no CompleteCertificateRefs (always an empty list).
 */
import { CodedError, ErrorCodes } from '../util/errors';
import { bytesEqual, decodeBase64Lenient } from '../util/bytes';
import { digestByOid } from '../trust/crypto';
import { xadesChildPath } from '../ocsp/extract';
import { parseCertificateDer } from '../xades/cert';
import { textContent, type XDocument, type XElement, type XNode } from '../xml/safe';

const CERT_REF_PATH = [
  'QualifyingProperties',
  'UnsignedProperties',
  'UnsignedSignatureProperties',
  'CompleteCertificateRefs',
  'CertRefs',
  'Cert',
] as const;

/** XML-DSig DigestMethod URIs → digest OIDs (DigestAlgorithm.ofUri). */
const DIGEST_URIS: Record<string, string> = {
  'http://www.w3.org/2000/09/xmldsig#sha1': '1.3.14.3.2.26',
  'http://www.w3.org/2001/04/xmlenc#sha256': '2.16.840.1.101.3.4.2.1',
  'http://www.w3.org/2001/04/xmldsig-more#sha384': '2.16.840.1.101.3.4.2.2',
  'http://www.w3.org/2001/04/xmlenc#sha512': '2.16.840.1.101.3.4.2.3',
};

function elementById(doc: XDocument, id: string): XElement | null {
  const want = id.startsWith('#') ? id.slice(1) : id;
  const all = doc.getElementsByTagName('*');
  for (let i = 0; i < all.length; i++) {
    const el = all.item(i) as XElement;
    if (el.getAttribute('Id') === want) return el;
  }
  return null;
}

function asElement(n: XNode | null, what: string): XElement {
  if (!n || n.nodeType !== 1) throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, `ClassCastException: ${what} is not an element`);
  return n as XElement;
}

export async function getExtraCertificates(doc: XDocument, object: XElement): Promise<Uint8Array[]> {
  const out: Uint8Array[] = [];
  for (const certRef of xadesChildPath(object, CERT_REF_PATH)) {
    const certId = certRef.getAttribute('URI');
    if (!certId) throw new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, 'Missing certificate id attribute');
    const certElem = elementById(doc, certId);
    if (!certElem) throw new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, `Could not find certificate with id ${certId}`);

    const der = decodeBase64Lenient(textContent(certElem));
    let serial: string;
    try {
      serial = parseCertificateDer(der).cert.serialNumber.toBigInt().toString();
    } catch (e) {
      throw new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, `Could not parse certificate: ${String(e)}`, { cause: e });
    }

    // Helper.verifyDigest((Element) certRef.getFirstChild(), cert.getEncoded())
    const certDigest = asElement(certRef.firstChild, 'xades:Cert first child');
    const method = asElement(certDigest.firstChild, 'CertDigest first child');
    const value = certDigest.lastChild;
    const oid = DIGEST_URIS[method.getAttribute('Algorithm') ?? ''];
    if (!oid || !value) {
      throw new CodedError(ErrorCodes.X_INTERNAL_ERROR, `Unsupported or missing digest method in certificate reference ${certId}`);
    }
    const expected = decodeBase64Lenient(textContent(value));
    if (!bytesEqual(expected, await digestByOid(oid, der))) {
      throw new CodedError(ErrorCodes.X_MALFORMED_SIGNATURE, `Certificate (${serial}) digest does not match`);
    }
    out.push(der);
  }
  return out;
}
