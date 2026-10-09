/**
 * Coded errors: the port of X-Road's CodedException / XrdRuntimeException.
 *
 * API:
 *   new CodedError(faultCode, faultString, { cause? })  - throw one
 *   err.withPrefix(prefix)                              - Java withPrefix
 *   translateException(e)                               - Java translateException
 *   isCodedError(e)                                     - type guard
 *   ErrorCodes.*                                        - the string values of the codes (lowercase)
 *
 * Fault codes are the lowercase string values used by X-Road 7.8.x
 * (e.g. 'malformed_signature'), never the Java constant names.
 */

export const ErrorCodes = {
  X_IO_ERROR: 'io_error',
  X_INTERNAL_ERROR: 'internal_error',
  X_CERT_VALIDATION: 'cert_validation',
  X_INCORRECT_VALIDATION_INFO: 'incorrect_validation_info',
  X_CANNOT_CREATE_CERT_PATH: 'cannot_create_cert_path',
  X_INCORRECT_CERTIFICATE: 'incorrect_certificate',
  X_INVALID_SIGNATURE_VALUE: 'invalid_signature_value',
  X_MALFORMED_SIGNATURE: 'malformed_signature',
  X_INVALID_XML: 'invalid_xml',
  X_INVALID_REFERENCE: 'invalid_reference',
  X_INVALID_CERT_PATH_X: 'invalid_cert_path',
  X_INVALID_HASH_CHAIN_RESULT: 'invalid_hash_chain',
  X_MALFORMED_HASH_CHAIN: 'malformed_hash_chain',
  X_HASHCHAIN_UNUSED_INPUTS: 'hashchain_unused_inputs',
  X_INVALID_HASH_CHAIN_REF: 'invalid_hash_chain_ref',
  X_INVALID_SOAP: 'invalid_soap',
  X_INVALID_BODY: 'invalid_body',
  X_MISSING_BODY: 'missing_body',
  X_MISSING_HEADER: 'missing_header',
  X_MISSING_HEADER_FIELD: 'missing_header_field',
  X_DUPLICATE_HEADER_FIELD: 'duplicate_header_field',
  X_INCONSISTENT_HEADERS: 'inconsistent_headers',
  X_INVALID_PROTOCOL_VERSION: 'invalid_protocol_version',
  X_ASIC_MIME_TYPE_NOT_FOUND: 'asic_mime_type_not_found',
  X_ASIC_INVALID_MIME_TYPE: 'asic_invalid_mime_type',
  X_ASIC_MESSAGE_NOT_FOUND: 'asic_message_not_found',
  X_ASIC_SIGNATURE_NOT_FOUND: 'asic_signature_not_found',
  X_ASIC_HASH_CHAIN_RESULT_NOT_FOUND: 'asic_hash_chain_result_not_found',
  X_ASIC_HASH_CHAIN_NOT_FOUND: 'asic_hash_chain_not_found',
  X_ASIC_TIMESTAMP_NOT_FOUND: 'asic_timestamp_not_found',
  X_ASIC_MANIFEST_NOT_FOUND: 'asic_manifest_not_found',
  NO_TIMESTAMPING_PROVIDER_FOUND: 'mlog.no_timestamping_provider_found',
  TIMESTAMP_TOKEN_SIGNER_INFO_NOT_FOUND: 'mlog.timestamp_token_signer_info_not_found',
  TSP_CERTIFICATE_NOT_FOUND: 'mlog.tsp_certificate_not_found',
  TIMESTAMP_SIGNER_VERIFICATION_FAILED: 'mlog.timestamp_signer_verification_failed',
  INVALID_CERTIFICATE: 'invalid_certificate',
  /**
   * Port-only (no Java equivalent): a size or count limit from ContainerLimits
   * was exceeded. Never produced by well-formed containers.
   */
  XRAV_LIMIT_EXCEEDED: 'xrav.limit_exceeded',
} as const;

export class CodedError extends Error {
  readonly faultCode: string;
  readonly faultString: string;

  constructor(faultCode: string, faultString: string, options?: { cause?: unknown }) {
    super(`${faultCode}: ${faultString}`, options);
    this.name = 'CodedError';
    this.faultCode = faultCode;
    this.faultString = faultString;
  }

  /** Java CodedException.withPrefix: `p.code` unless the code already starts with p. */
  withPrefix(prefix: string): CodedError {
    if (this.faultCode.startsWith(prefix)) return this;
    return new CodedError(`${prefix}.${this.faultCode}`, this.faultString, { cause: this.cause });
  }
}

export function isCodedError(e: unknown): e is CodedError {
  return e instanceof CodedError;
}

/**
 * Java translateException: a CodedError is kept (code lowercased); anything
 * else becomes `internal_error` with the error's message. Callers that need
 * the Java exception-type mapping (IOException → io_error, SAXException →
 * invalid_xml, ...) must throw a CodedError with that code themselves.
 */
export function translateException(e: unknown): CodedError {
  if (e instanceof CodedError) {
    const lower = e.faultCode.toLowerCase();
    return lower === e.faultCode ? e : new CodedError(lower, e.faultString, { cause: e.cause });
  }
  const msg = e instanceof Error ? e.message : String(e);
  return new CodedError(ErrorCodes.X_INTERNAL_ERROR, msg, { cause: e });
}
