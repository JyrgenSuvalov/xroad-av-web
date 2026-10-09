/**
 * Santuario's base64 and text extraction (SANTUARIO-RULES §4).
 *
 *   dsText(el)          - XMLUtils.getFullTextChildrenFromNode: the direct Text
 *                         children only (CDATA sections and nested elements are skipped)
 *   decodeDsBase64(s)   - XMLUtils.decode = java.util.Base64.getMimeDecoder().decode
 *
 * The MIME decoder is lenient: any character outside the base64 alphabet is
 * ignored, and missing padding is accepted. It throws IllegalArgumentException
 * for a dangling single character in the last quantum, '=' at a quantum
 * boundary, "xx=" not immediately followed by '=', and alphabet characters
 * after the padding. Here that is
 *   internal_error "IllegalArgumentException: …" (an uncoded RuntimeException in X-Road).
 */
import { CodedError, ErrorCodes } from '../util/errors';
import type { XNode, XText } from '../xml/safe';

const TEXT_NODE = 3;

export function dsText(el: XNode): string {
  let s = '';
  for (let n = el.firstChild; n; n = n.nextSibling) if (n.nodeType === TEXT_NODE) s += (n as XText).data;
  return s;
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const VALUE = new Int8Array(256).fill(-1);
for (let i = 0; i < 64; i++) VALUE[ALPHABET.charCodeAt(i)] = i;
VALUE['='.charCodeAt(0)] = -2;

/** java.util.Base64.Decoder.decode0 with isMIME = true (JDK 21). The string is taken as ISO-8859-1. */
function value(c: number): number {
  return c < 256 ? VALUE[c]! : -1;
}

const iae = (msg: string) => new CodedError(ErrorCodes.X_INTERNAL_ERROR, `IllegalArgumentException: ${msg}`);

export function decodeDsBase64(s: string): Uint8Array {
  const out: number[] = [];
  let bits = 0;
  let shiftto = 18;
  let sp = 0;
  const sl = s.length;
  while (sp < sl) {
    const b = value(s.charCodeAt(sp++));
    if (b < 0) {
      if (b === -2) {
        if ((shiftto === 6 && (sp === sl || s.charCodeAt(sp++) !== 0x3d)) || shiftto === 18) {
          throw iae('Input byte array has wrong 4-byte ending unit');
        }
        break;
      }
      continue;
    }
    bits |= b << shiftto;
    shiftto -= 6;
    if (shiftto < 0) {
      out.push((bits >> 16) & 0xff, (bits >> 8) & 0xff, bits & 0xff);
      shiftto = 18;
      bits = 0;
    }
  }
  if (shiftto === 6) out.push((bits >> 16) & 0xff);
  else if (shiftto === 0) out.push((bits >> 16) & 0xff, (bits >> 8) & 0xff);
  else if (shiftto === 12) throw iae('Last unit does not have enough valid bits');
  while (sp < sl) {
    if (value(s.charCodeAt(sp++)) < 0) continue;
    throw iae(`Input byte array has incorrect ending byte at ${sp}`);
  }
  return Uint8Array.from(out);
}
