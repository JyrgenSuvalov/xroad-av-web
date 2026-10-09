// Error taxonomy

export type GlobalConfErrorCode =
  | 'ANCHOR_INVALID'
  | 'FETCH_FAILED'
  | 'DIRECTORY_MALFORMED'
  | 'SIGNATURE_MALFORMED'
  | 'VERIFICATION_CERT_NOT_FOUND'
  | 'SIGNATURE_INVALID'
  | 'UNSUPPORTED_ALGORITHM'
  | 'PART_HASH_MISMATCH'
  | 'INSTANCE_MISMATCH'
  | 'SHARED_PARAMS_INVALID'
  | 'ROLLBACK';

/**
 * Codes that mean "someone tampered with or forged the configuration".
 * They put the poller into the `failed` state even when a last-good
 * configuration exists.
 */
export const HARD_FAILURE_CODES: ReadonlySet<GlobalConfErrorCode> = new Set([
  'ANCHOR_INVALID',
  'SIGNATURE_MALFORMED',
  'VERIFICATION_CERT_NOT_FOUND',
  'SIGNATURE_INVALID',
  'UNSUPPORTED_ALGORITHM',
  'PART_HASH_MISMATCH',
  'INSTANCE_MISMATCH',
]);

export class GlobalConfError extends Error {
  readonly code: GlobalConfErrorCode;

  constructor(code: GlobalConfErrorCode, message: string, options?: { cause?: unknown }) {
    super(`${code}: ${message}`, options);
    this.name = 'GlobalConfError';
    this.code = code;
  }

  get hard(): boolean {
    return HARD_FAILURE_CODES.has(this.code);
  }
}

export function isGlobalConfError(e: unknown): e is GlobalConfError {
  return e instanceof GlobalConfError;
}
