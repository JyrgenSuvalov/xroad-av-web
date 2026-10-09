/**
 * Minimal, bounded zip reader (central directory, with local-header consistency
 * checks). Inflation is streamed through fflate and aborted as soon as a limit
 * is exceeded, so declared sizes are never trusted for allocation.
 *
 *   readZipEntries(bytes, limits) → { name, data }[] in central-directory order
 *   - input not starting with a local file header → [] (Java ZipInputStream
 *     yields no entries for such input)
 *   - corrupt structure, CRC mismatch, unsupported method/encryption/zip64 → CodedError io_error
 *   - limit exceeded → CodedError xrav.limit_exceeded
 */
import { Inflate } from 'fflate';
import { crc32, decodeUtf8 } from '../util/bytes';
import { CodedError, ErrorCodes } from '../util/errors';

export interface ContainerLimits {
  /** Max size of the container file itself. */
  maxContainerBytes: number;
  /** Max uncompressed size of a single entry. */
  maxEntryBytes: number;
  /** Max total uncompressed size of all entries. */
  maxTotalBytes: number;
  /** Max number of entries. */
  maxEntries: number;
}

export const DEFAULT_LIMITS: ContainerLimits = {
  maxContainerBytes: 64 * 1024 * 1024,
  maxEntryBytes: 64 * 1024 * 1024,
  maxTotalBytes: 256 * 1024 * 1024,
  maxEntries: 1000,
};

export interface ZipEntry {
  name: string;
  data: Uint8Array;
}

const ioError = (msg: string) => new CodedError(ErrorCodes.X_IO_ERROR, msg);
const limitError = (msg: string) => new CodedError(ErrorCodes.XRAV_LIMIT_EXCEEDED, msg);

export function readZipEntries(bytes: Uint8Array, limits: ContainerLimits = DEFAULT_LIMITS): ZipEntry[] {
  if (bytes.length > limits.maxContainerBytes) {
    throw limitError(`Container is larger than ${limits.maxContainerBytes} bytes`);
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (o: number) => dv.getUint16(o, true);
  const u32 = (o: number) => dv.getUint32(o, true);
  if (bytes.length < 4 || u32(0) !== 0x04034b50) return [];

  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 0xffff); i--) {
    if (u32(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw ioError('End of central directory not found');
  const count = u16(eocd + 10);
  let off = u32(eocd + 16);
  if (count === 0xffff || off === 0xffffffff) throw ioError('ZIP64 is not supported');
  if (count > limits.maxEntries) throw limitError(`More than ${limits.maxEntries} entries`);

  const entries: ZipEntry[] = [];
  let total = 0;
  for (let i = 0; i < count; i++) {
    if (off + 46 > bytes.length || u32(off) !== 0x02014b50) throw ioError('Corrupt central directory');
    const flags = u16(off + 8);
    const method = u16(off + 10);
    const crc = u32(off + 16);
    const csize = u32(off + 20);
    const usize = u32(off + 24);
    const nlen = u16(off + 28);
    const elen = u16(off + 30);
    const clen = u16(off + 32);
    const loff = u32(off + 42);
    if (off + 46 + nlen > bytes.length) throw ioError('Corrupt central directory');
    const rawName = bytes.subarray(off + 46, off + 46 + nlen);
    const name = decodeUtf8(rawName);
    off += 46 + nlen + elen + clen;

    if (flags & 1) throw ioError(`Encrypted entry: ${name}`);
    if (loff + 30 > bytes.length || u32(loff) !== 0x04034b50) throw ioError(`Bad local header: ${name}`);
    const lnlen = u16(loff + 26);
    const lelen = u16(loff + 28);
    const lname = bytes.subarray(loff + 30, loff + 30 + lnlen);
    if (lnlen !== nlen || !lname.every((b, j) => b === rawName[j])) {
      throw ioError(`Local header name mismatch: ${name}`);
    }
    const start = loff + 30 + lnlen + lelen;
    if (start + csize > bytes.length) throw ioError(`Truncated entry: ${name}`);
    const comp = bytes.subarray(start, start + csize);
    if (name.endsWith('/') && usize === 0) continue; // directory

    if (usize > limits.maxEntryBytes) throw limitError(`Entry ${name} is larger than ${limits.maxEntryBytes} bytes`);
    const budget = Math.min(limits.maxEntryBytes, limits.maxTotalBytes - total);
    let data: Uint8Array;
    if (method === 0) {
      data = comp.slice();
    } else if (method === 8) {
      data = inflateBounded(comp, budget, name);
    } else {
      throw ioError(`Unsupported compression method ${method}: ${name}`);
    }
    if (data.length > budget) throw limitError(`Uncompressed size limit exceeded at ${name}`);
    if (data.length !== usize) throw ioError(`Size mismatch: ${name}`);
    if (crc32(data) !== crc) throw ioError(`CRC mismatch: ${name}`);
    total += data.length;
    entries.push({ name, data });
  }
  return entries;
}

function inflateBounded(comp: Uint8Array, budget: number, name: string): Uint8Array {
  const chunks: Uint8Array[] = [];
  let size = 0;
  let done = false;
  const inf = new Inflate((chunk, final) => {
    size += chunk.length;
    if (size > budget) throw limitError(`Uncompressed size limit exceeded at ${name}`);
    chunks.push(chunk);
    if (final) done = true;
  });
  const STEP = 16 * 1024;
  try {
    for (let i = 0; i < comp.length; i += STEP) {
      const end = Math.min(comp.length, i + STEP);
      inf.push(comp.subarray(i, end), end === comp.length);
    }
    if (comp.length === 0) inf.push(new Uint8Array(0), true);
  } catch (e) {
    if (e instanceof CodedError) throw e;
    throw ioError(`Invalid deflate data in ${name}: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (!done && size === 0 && comp.length > 0) throw ioError(`Invalid deflate data in ${name}`);
  const out = new Uint8Array(size);
  let p = 0;
  for (const c of chunks) {
    out.set(c, p);
    p += c.length;
  }
  return out;
}
