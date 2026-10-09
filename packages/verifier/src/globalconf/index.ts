// Global configuration: anchor → signed directory → shared-params → TrustContext.
// Overview: docs/architecture.md.

export { type AnchorSource, type ConfigurationAnchor, anchorCerts, parseAnchor } from './anchor';
export {
  type DirectoryPart,
  type VerifiedDirectory,
  type VerifyDirectoryOptions,
  confVersionOf,
  verifyDirectory,
} from './directory';
export { GlobalConfError, type GlobalConfErrorCode, HARD_FAILURE_CODES, isGlobalConfError } from './errors';
export { type FetchConfOptions, type FetchLike, type VerifiedConf, fetchVerifiedConf, loadAnchor } from './fetch';
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
  type SharedParams,
  type SharedParamsCa,
  type SharedParamsTsa,
  parseNextUpdateParams,
  parseSharedParams,
} from './sharedParams';
export { type InstanceTrustInput, type TrustContextInput, buildTrustContext, instanceTrust, toTrustedCert } from './trust';
