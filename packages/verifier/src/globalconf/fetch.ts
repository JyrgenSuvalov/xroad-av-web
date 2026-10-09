// Download + verify the configuration through the same-origin proxy.

import type { TrustContext } from '../types';
import { type ConfigurationAnchor, parseAnchor } from './anchor';
import { bytesEqual } from '../util/bytes';
import { digest } from './crypto';
import { type DirectoryPart, type VerifiedDirectory, confVersionOf, verifyDirectory } from './directory';
import { GlobalConfError } from './errors';
import { type SharedParams, parseNextUpdateParams, parseSharedParams } from './sharedParams';
import { buildTrustContext, instanceTrust } from './trust';

/** The subset of `fetch` we use; injected so tests run offline. */
export type FetchLike = (
  url: string,
  init?: { signal?: AbortSignal; cache?: 'no-store' },
) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>;

export interface FetchConfOptions {
  /** Proxy prefix. Default '/globalconf'. */
  base?: string;
  /** Directory version to request first (default 6); steps down to 2 on 404 only. */
  version?: number;
  /** Per-request timeout (default 30 s, as confclient's read timeout). */
  timeoutMs?: number;
  /** Clock for the anchor-cert validity check. */
  now?: Date;
}

export interface VerifiedConf {
  instanceIdentifier: string;
  directory: VerifiedDirectory;
  /** Directory URL actually used (with ?version=). */
  directoryUrl: string;
  sharedParams: SharedParams;
  verifyOcspNextUpdate: boolean;
  /** `V<n>/<timestamp>` of SHARED-PARAMETERS (confVersionOf). */
  confVersion: string;
  expireDate: Date;
  trust: TrustContext;
}

export const MIN_VERSION = 2;
export const CURRENT_VERSION = 6;

class NotFound extends Error {}

async function get(fetchFn: FetchLike, url: string, timeoutMs: number): Promise<Uint8Array> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    let res;
    try {
      res = await fetchFn(url, { signal: ctrl.signal, cache: 'no-store' });
    } catch (e) {
      throw new GlobalConfError('FETCH_FAILED', `GET ${url}: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
    }
    if (res.status === 404) throw new NotFound(url);
    if (!res.ok) throw new GlobalConfError('FETCH_FAILED', `GET ${url}: HTTP ${res.status}`);
    try {
      return new Uint8Array(await res.arrayBuffer());
    } catch (e) {
      throw new GlobalConfError('FETCH_FAILED', `GET ${url}: body: ${String(e)}`, { cause: e });
    }
  } finally {
    clearTimeout(timer);
  }
}

/**
 * VersionRangeResolver parity: probe `?version=N` for N = start..3 and step
 * down only on 404; version 2 is used without probing.
 */
async function getDirectory(
  fetchFn: FetchLike,
  dirPath: string,
  start: number,
  timeoutMs: number,
): Promise<{ url: string; version: number; bytes: Uint8Array }> {
  for (let v = start; v >= MIN_VERSION; v--) {
    const url = `${dirPath}?version=${v}`;
    try {
      return { url, version: v, bytes: await get(fetchFn, url, timeoutMs) };
    } catch (e) {
      if (!(e instanceof NotFound) || v === MIN_VERSION) {
        if (e instanceof NotFound) throw new GlobalConfError('FETCH_FAILED', `GET ${url}: HTTP 404`);
        throw e;
      }
    }
  }
  throw new GlobalConfError('FETCH_FAILED', 'no directory version available');
}

async function getPart(
  fetchFn: FetchLike,
  base: string,
  part: DirectoryPart,
  timeoutMs: number,
): Promise<Uint8Array> {
  // Content-location is host-absolute on the central server and was checked
  // against /^\/V\d+\/\d+\/[A-Za-z0-9._-]+$/, so prefixing keeps us same-origin.
  const bytes = await get(fetchFn, base + part.contentLocation, timeoutMs);
  if (!bytesEqual(await digest(part.hashAlgorithmId, bytes), part.hash)) {
    throw new GlobalConfError('PART_HASH_MISMATCH', `${part.contentLocation}: hash does not match the signed directory`);
  }
  return bytes;
}

/** Fetch, verify and parse the global configuration. Throws GlobalConfError. */
export async function fetchVerifiedConf(
  fetchFn: FetchLike,
  anchor: ConfigurationAnchor,
  options: FetchConfOptions = {},
): Promise<VerifiedConf> {
  const base = (options.base ?? '/globalconf').replace(/\/$/, '');
  const timeoutMs = options.timeoutMs ?? 30_000;
  const firstSource = anchor.sources[0];
  if (!firstSource) throw new GlobalConfError('ANCHOR_INVALID', 'no source');
  let dirPath: string;
  try {
    dirPath = base + new URL(firstSource.downloadURL).pathname;
  } catch {
    throw new GlobalConfError('ANCHOR_INVALID', `bad downloadURL ${firstSource.downloadURL}`);
  }

  // Old <ts>/ directories live 600 s, but if a part 404s anyway, refetch the directory once.
  for (let attempt = 0; ; attempt++) {
    const dir = await getDirectory(fetchFn, dirPath, options.version ?? CURRENT_VERSION, timeoutMs);
    const directory = await verifyDirectory(dir.bytes, anchor, {
      expectedVersion: dir.version,
      ...(options.now ? { now: options.now } : {}),
    });
    try {
      const spBytes = await getPart(fetchFn, base, directory.sharedParams, timeoutMs);
      const sharedParams = parseSharedParams(spBytes);
      if (sharedParams.instanceIdentifier !== directory.sharedParams.instance) {
        throw new GlobalConfError(
          'INSTANCE_MISMATCH',
          `shared-params instanceIdentifier '${sharedParams.instanceIdentifier}' ≠ part instance '${directory.sharedParams.instance}'`,
        );
      }
      let verifyOcspNextUpdate = true;
      if (directory.nextUpdate) {
        verifyOcspNextUpdate = parseNextUpdateParams(await getPart(fetchFn, base, directory.nextUpdate, timeoutMs));
      }
      const confVersion = confVersionOf(directory.sharedParams.contentLocation);
      const trust = buildTrustContext({
        mainInstance: anchor.instanceIdentifier,
        verifyOcspNextUpdate,
        instances: [instanceTrust({ sharedParams, confVersion, expiresAt: directory.expireDate })],
      });
      return {
        instanceIdentifier: anchor.instanceIdentifier,
        directory,
        directoryUrl: dir.url,
        sharedParams,
        verifyOcspNextUpdate,
        confVersion,
        expireDate: directory.expireDate,
        trust,
      };
    } catch (e) {
      if (e instanceof NotFound) {
        if (attempt === 0) continue;
        throw new GlobalConfError('FETCH_FAILED', `GET ${e.message}: HTTP 404`);
      }
      throw e;
    }
  }
}

/** Load and parse the configuration anchor served next to the app (default `/anchor.xml`). */
export async function loadAnchor(fetchFn: FetchLike, url = '/anchor.xml', timeoutMs = 30_000): Promise<ConfigurationAnchor> {
  let bytes: Uint8Array;
  try {
    bytes = await get(fetchFn, url, timeoutMs);
  } catch (e) {
    if (e instanceof NotFound) throw new GlobalConfError('ANCHOR_INVALID', `GET ${url}: HTTP 404`);
    throw e;
  }
  return parseAnchor(new TextDecoder('utf-8').decode(bytes));
}
