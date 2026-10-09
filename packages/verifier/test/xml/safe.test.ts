import { describe, expect, it } from 'vitest';
import { canonicalizeToString } from '../../src/c14n/c14n';
import { CodedError, translateException } from '../../src/util/errors';
import { decodeBase64Lenient, isJavaBlank } from '../../src/util/bytes';
import { firstElementByTagName, parseXml } from '../../src/xml/safe';

describe('parseXml', () => {
  it('rejects DOCTYPE and entity declarations', () => {
    expect(() => parseXml('<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>')).toThrow(CodedError);
  });
  it('rejects malformed XML with the given code', () => {
    try {
      parseXml('<a><b></a>', 'invalid_soap');
      expect.unreachable();
    } catch (e) {
      expect((e as CodedError).faultCode).toBe('invalid_soap');
    }
  });
  it('drops comments, merges text, keeps &#13; and U+2028', () => {
    const d = parseXml('<a>x<!--c-->y&#13;\r\n </a>');
    expect(d.documentElement!.textContent).toBe('xy\r\n ');
  });
  it('matches by literal qualified name', () => {
    const d = parseXml('<r xmlns:ds="u" xmlns:x="u"><x:Signature/><ds:Signature/></r>');
    expect(firstElementByTagName(d, 'ds:Signature')?.prefix).toBe('ds');
  });
});

describe('c14n', () => {
  it('renders in-scope namespaces and inherited xml:* on the apex, sorted', () => {
    const d = parseXml('<r xmlns="d" xmlns:b="B" xmlns:a="A" xml:lang="en"><a:x z="1" a:y="&lt;&#9;" b="2">t&gt;&#13;</a:x></r>');
    const x = firstElementByTagName(d, 'a:x')!;
    expect(canonicalizeToString(x)).toBe(
      '<a:x xmlns="d" xmlns:a="A" xmlns:b="B" b="2" z="1" a:y="&lt;&#x9;" xml:lang="en">t&gt;&#xD;</a:x>',
    );
  });
  it('omits superfluous redeclarations in descendants', () => {
    const d = parseXml('<r xmlns:a="A"><a:x><a:y xmlns:a="A"/></a:x></r>');
    expect(canonicalizeToString(firstElementByTagName(d, 'a:x')!)).toBe('<a:x xmlns:a="A"><a:y></a:y></a:x>');
  });
});

describe('util', () => {
  it('translateException', () => {
    expect(translateException(new Error('boom')).faultCode).toBe('internal_error');
    expect(new CodedError('invalid_hash_chain', 's').withPrefix('malformed_signature').faultCode).toBe(
      'malformed_signature.invalid_hash_chain',
    );
  });
  it('Java blank and lenient base64', () => {
    expect(isJavaBlank(' ')).toBe(false);
    expect(isJavaBlank(' \t ')).toBe(true);
    expect(new TextDecoder().decode(decodeBase64Lenient('QU\r\nJD*'))).toBe('ABC');
  });
});
