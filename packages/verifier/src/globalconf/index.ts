// Global configuration: anchor → signed directory → shared-params → TrustContext.
// Overview: docs/architecture.md.

export { type AnchorSource, anchorCerts, type ConfigurationAnchor, parseAnchor } from './anchor';
export {
  confVersionOf,
  type DirectoryPart,
  type VerifiedDirectory,
  type VerifyDirectoryOptions,
  verifyDirectory,
} from './directory';
export { GlobalConfError, type GlobalConfErrorCode, HARD_FAILURE_CODES, isGlobalConfError } from './errors';
export { type FetchConfOptions, type FetchLike, fetchVerifiedConf, loadAnchor, type VerifiedConf } from './fetch';
export {
  ConfPoller,
  type ConfPollerOptions,
  type PolledConf,
  type PollerError,
  type PollerState,
  type PollerStatus,
  type TimerLike,
} from './poller';
export {
  type CaInfo,
  type Member,
  type OcspInfo,
  parseNextUpdateParams,
  parseSharedParams,
  type SharedParams,
  type SharedParamsCa,
  type SharedParamsTsa,
} from './sharedParams';
export {
  buildTrustContext,
  type InstanceTrustInput,
  instanceTrust,
  type TrustContextInput,
  toTrustedCert,
} from './trust';
