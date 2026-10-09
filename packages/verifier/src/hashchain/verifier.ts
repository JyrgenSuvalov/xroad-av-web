/**
 * Port of X-Road 7.8.3 HashChainVerifier (HCV:199-529), with
 * the 7.8.3 hardening: memoised steps, cycle detection, depth 64,
 * 1024 steps, 10000 values.
 *
 *   await verifyHashChain(resultXml, resolver, inputs)
 *
 * `inputs` are the URIs that must be referenced by some DataRef. In ASiC every
 * input digest is null (no precomputed shortcut), so only the names are taken.
 *
 * Fault codes (CodedError, unprefixed; callers add prefixes):
 *   malformed_hash_chain   "Parsing hash chain failed" (result or chain XML)
 *                          "Invalid hash step URI: <uri>" (no fragment / unknown step id)
 *                          "Cycle detected in hash chain at step: <full uri>"
 *                          "Hash chain exceeds maximum depth of 64"
 *                          "Hash chain exceeds maximum step count of 1024"
 *                          "Hash chain exceeds maximum value count of 10000"
 *   invalid_reference      "Cannot resolve URI: <uri>" (chain document or DataRef data missing)
 *   invalid_hash_chain_ref "Invalid digest value in hash chain reference to <uri>"
 *   invalid_hash_chain     "Hash chain result does not match hash chain calculation"
 *   hashchain_unused_inputs "Some inputs were not referenced by hash chain: <uris>"
 *   internal_error         Java NPEs (no digest method and no DefaultDigestMethod;
 *                          result without DigestMethod; '#frag' with no current chain),
 *                          unknown/unsupported digest algorithm when digesting,
 *                          and DataRef with ds:Transforms (port deviation: X-Road
 *                          never produces them; Java would apply them).
 */
import { CodedError, ErrorCodes } from '../util/errors';
import { bytesEqual, decodeUtf8 } from '../util/bytes';
import { encodeDigestList, type DigestValue } from './der';
import { digest } from './digest';
import {
  parseHashChain,
  parseHashChainResult,
  type DataRefModel,
  type HashChainModel,
  type HashStepModel,
  type HashValueOrRef,
} from './parse';

export const MAX_DEPTH = 64;
export const MAX_STEPS = 1024;
export const MAX_VALUES = 10_000;

/** HashChainReferenceResolver. */
export interface HashChainReferenceResolver {
  /** False → the DataRef's DigestValue is trusted as-is (and typically logged). */
  shouldResolve(uri: string, digestValue: Uint8Array): boolean;
  /** Bytes of the referenced document, or null if it cannot be resolved. */
  resolve(uri: string): Uint8Array | null;
}

const npe = (what: string) => new CodedError(ErrorCodes.X_INTERNAL_ERROR, `NullPointerException: ${what}`);
const malformed = (msg: string) => new CodedError(ErrorCodes.X_MALFORMED_HASH_CHAIN, msg);

export async function verifyHashChain(
  resultXml: string,
  resolver: HashChainReferenceResolver,
  inputs: Iterable<string>,
): Promise<void> {
  await new HashChainVerifier(resolver, new Set(inputs)).verify(resultXml);
}

class HashChainVerifier {
  private readonly chainCache = new Map<string, HashChainModel>();
  private readonly chainBaseUris = new Map<HashChainModel, string>();
  private readonly resolvedSteps = new Map<string, Uint8Array>();
  private readonly activePath = new Set<string>();
  private totalSteps = 0;
  private totalValues = 0;
  private readonly usedInputs = new Set<string>();

  constructor(
    private readonly resolver: HashChainReferenceResolver,
    private readonly inputs: ReadonlySet<string>,
  ) {}

  async verify(resultXml: string): Promise<void> {
    const result = parseHashChainResult(resultXml);
    if (result.uri === null) throw npe('hash chain result URI is null');
    const stepData = await this.resolveHashStep(result.uri, null);
    if (result.digestMethod === undefined) throw npe('hash chain result has no DigestMethod');
    const calculated = await digest(result.digestMethod, stepData);
    if (!bytesEqual(calculated, result.digestValue!)) {
      throw new CodedError(
        ErrorCodes.X_INVALID_HASH_CHAIN_RESULT,
        'Hash chain result does not match hash chain calculation',
      );
    }
    const unused = [...this.inputs].filter((i) => !this.usedInputs.has(i));
    if (unused.length > 0) {
      throw new CodedError(
        ErrorCodes.X_HASHCHAIN_UNUSED_INPUTS,
        `Some inputs were not referenced by hash chain: ${unused.join(', ')}`,
      );
    }
  }

  private async resolveHashStep(uri: string, current: HashChainModel | null): Promise<Uint8Array> {
    const hashIndex = uri.indexOf('#');
    const base = hashIndex < 0 ? uri : uri.slice(0, hashIndex);
    const fragment = hashIndex < 0 ? null : uri.slice(hashIndex + 1);
    const fullUri = this.buildFullUri(base, fragment, current);

    const memo = this.resolvedSteps.get(fullUri);
    if (memo) return memo;
    if (this.activePath.has(fullUri)) throw malformed(`Cycle detected in hash chain at step: ${fullUri}`);
    if (this.activePath.size >= MAX_DEPTH) throw malformed(`Hash chain exceeds maximum depth of ${MAX_DEPTH}`);
    if (this.totalSteps >= MAX_STEPS) throw malformed(`Hash chain exceeds maximum step count of ${MAX_STEPS}`);

    this.activePath.add(fullUri);
    this.totalSteps++;
    try {
      const [step, chain] = this.fetchHashStep(base, fragment, current);
      const tooMany = () => malformed(`Hash chain exceeds maximum value count of ${MAX_VALUES}`);
      if (step.values.length > MAX_VALUES - this.totalValues) throw tooMany();
      const digests: DigestValue[] = [];
      for (const v of step.values) {
        this.totalValues++;
        if (this.totalValues > MAX_VALUES) throw tooMany();
        digests.push(await this.resolveValue(v, chain));
      }
      const bytes = encodeDigestList(digests);
      this.resolvedSteps.set(fullUri, bytes);
      return bytes;
    } finally {
      this.activePath.delete(fullUri);
    }
  }

  private buildFullUri(base: string, fragment: string | null, current: HashChainModel | null): string {
    if (fragment === null || base !== '') return base + (fragment !== null ? `#${fragment}` : '');
    if (current === null) return `#${fragment}`;
    const chainBase = this.chainBaseUris.get(current);
    if (chainBase === undefined) throw npe('chain base URI missing');
    return `${chainBase}#${fragment}`;
  }

  private fetchHashStep(
    base: string,
    fragment: string | null,
    current: HashChainModel | null,
  ): [HashStepModel, HashChainModel] {
    const rawUri = base + (fragment !== null ? `#${fragment}` : '');
    if (fragment === null || fragment === '') throw malformed(`Invalid hash step URI: ${rawUri}`);
    const chain = base === '' ? current : this.getHashChain(base);
    if (chain === null) throw npe('current hash chain is null');
    const step = chain.steps.find((s) => s.id === fragment);
    if (!step) throw malformed(`Invalid hash step URI: ${rawUri}`);
    return [step, chain];
  }

  private getHashChain(uri: string): HashChainModel {
    let chain = this.chainCache.get(uri);
    if (!chain) {
      const data = this.resolver.resolve(uri);
      if (data === null) throw new CodedError(ErrorCodes.X_INVALID_REFERENCE, `Cannot resolve URI: ${uri}`);
      chain = parseHashChain(decodeUtf8(data));
      this.chainCache.set(uri, chain);
      this.chainBaseUris.set(chain, uri);
    }
    return chain;
  }

  private valueAlgorithm(v: HashValueOrRef, chain: HashChainModel): string {
    const alg = v.digestMethod ?? chain.defaultDigestMethod;
    if (alg === undefined) throw npe('no DigestMethod and no DefaultDigestMethod');
    return alg;
  }

  private async resolveValue(v: HashValueOrRef, chain: HashChainModel): Promise<DigestValue> {
    switch (v.kind) {
      case 'DataRef':
        return this.resolveDataRef(v, chain);
      case 'StepRef': {
        const resolved = await this.resolveHashStep(v.uri, chain);
        const algorithm = this.valueAlgorithm(v, chain);
        return { algorithm, value: await digest(algorithm, resolved) };
      }
      case 'HashValue':
        // Transforms on a HashValue are ignored (Java: "everything is already done").
        return { algorithm: this.valueAlgorithm(v, chain), value: v.digestValue };
    }
  }

  private async resolveDataRef(ref: DataRefModel, chain: HashChainModel): Promise<DigestValue> {
    if (this.inputs.has(ref.uri)) this.usedInputs.add(ref.uri);
    const algorithm = this.valueAlgorithm(ref, chain);
    if (!this.resolver.shouldResolve(ref.uri, ref.digestValue)) return { algorithm, value: ref.digestValue };
    if (ref.hasTransforms) {
      throw new CodedError(
        ErrorCodes.X_INTERNAL_ERROR,
        `Transforms in hash chain references are not supported: ${ref.uri}`,
      );
    }
    const data = this.resolver.resolve(ref.uri);
    if (data === null) throw new CodedError(ErrorCodes.X_INVALID_REFERENCE, `Cannot resolve URI: ${ref.uri}`);
    const calculated = await digest(algorithm, data);
    if (!bytesEqual(calculated, ref.digestValue)) {
      throw new CodedError(
        ErrorCodes.X_INVALID_HASH_CHAIN_REF,
        `Invalid digest value in hash chain reference to ${ref.uri}`,
      );
    }
    return { algorithm, value: calculated };
  }
}
