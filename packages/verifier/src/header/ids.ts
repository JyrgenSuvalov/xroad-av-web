/**
 * X-Road identifiers (port of common-domain identifier/*.java, 7.8.3).
 *
 *   ClientId / ServiceId / SecurityServerId - plain data, display-friendly
 *   createClientId(...)        - ClientId.Conf.create validation (blank → error)
 *   createServiceId(...)       - ServiceId.Conf.create validation (subsystem NOT checked)
 *   createSecurityServerId(...)
 *   serviceClientId(service)   - ServiceId.getClientId() (re-validates the subsystem)
 *   clientIdToString / serviceIdToString / securityServerIdToString
 *       - XRoadId.toString(): `<TYPE>:<instance>/<field>/...`, null fields skipped,
 *         no escaping
 *
 * Validation failures are Java IllegalArgumentExceptions; here IdentifierError.
 */
import { isJavaBlank } from '../util/bytes';

export interface ClientId {
  /** MEMBER iff subsystemCode is null (the SOAP objectType attribute does not decide it). */
  readonly type: 'MEMBER' | 'SUBSYSTEM';
  readonly xRoadInstance: string;
  readonly memberClass: string;
  readonly memberCode: string;
  readonly subsystemCode: string | null;
}

export interface ServiceId {
  readonly xRoadInstance: string;
  readonly memberClass: string;
  readonly memberCode: string;
  /** Not validated by ServiceId.Conf.create: may be '' or blank. */
  readonly subsystemCode: string | null;
  readonly serviceCode: string;
  readonly serviceVersion: string | null;
}

export interface SecurityServerId {
  readonly xRoadInstance: string;
  readonly memberClass: string;
  readonly memberCode: string;
  readonly serverCode: string;
}

/** Java IllegalArgumentException from identifier validation (Validation.validateArgument). */
export class IdentifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentifierError';
  }
}

function req(field: string, v: string | null | undefined): string {
  if (v == null || isJavaBlank(v)) throw new IdentifierError(`${field} must not be blank`);
  return v;
}

function opt(field: string, v: string | null | undefined): string | null {
  return v == null ? null : req(field, v);
}

export function createClientId(
  xRoadInstance: string | null | undefined,
  memberClass: string | null | undefined,
  memberCode: string | null | undefined,
  subsystemCode: string | null | undefined,
): ClientId {
  const inst = req('xRoadInstance', xRoadInstance);
  const cls = req('memberClass', memberClass);
  const code = req('memberCode', memberCode);
  const sub = opt('subsystemCode', subsystemCode);
  return {
    type: sub == null ? 'MEMBER' : 'SUBSYSTEM',
    xRoadInstance: inst,
    memberClass: cls,
    memberCode: code,
    subsystemCode: sub,
  };
}

export function createServiceId(
  xRoadInstance: string | null | undefined,
  memberClass: string | null | undefined,
  memberCode: string | null | undefined,
  subsystemCode: string | null | undefined,
  serviceCode: string | null | undefined,
  serviceVersion: string | null | undefined,
): ServiceId {
  return {
    xRoadInstance: req('xRoadInstance', xRoadInstance),
    memberClass: req('memberClass', memberClass),
    memberCode: req('memberCode', memberCode),
    serviceCode: req('serviceCode', serviceCode),
    subsystemCode: subsystemCode ?? null,
    serviceVersion: serviceVersion ?? null,
  };
}

export function createSecurityServerId(
  xRoadInstance: string | null | undefined,
  memberClass: string | null | undefined,
  memberCode: string | null | undefined,
  serverCode: string | null | undefined,
): SecurityServerId {
  return {
    xRoadInstance: req('xRoadInstance', xRoadInstance),
    memberClass: req('memberClass', memberClass),
    memberCode: req('memberCode', memberCode),
    serverCode: req('serverCode', serverCode),
  };
}

/** ServiceId.getClientId(): ClientId.Conf.create(...), which validates the subsystem. */
export function serviceClientId(s: ServiceId): ClientId {
  return createClientId(s.xRoadInstance, s.memberClass, s.memberCode, s.subsystemCode);
}

function shortString(parts: readonly (string | null)[]): string {
  return parts.filter((p): p is string => p != null).join('/');
}

export function clientIdToString(id: ClientId): string {
  const type = id.subsystemCode == null ? 'MEMBER' : 'SUBSYSTEM';
  return `${type}:${shortString([id.xRoadInstance, id.memberClass, id.memberCode, id.subsystemCode])}`;
}

export function serviceIdToString(id: ServiceId): string {
  return `SERVICE:${shortString([
    id.xRoadInstance,
    id.memberClass,
    id.memberCode,
    id.subsystemCode,
    id.serviceCode,
    id.serviceVersion,
  ])}`;
}

export function securityServerIdToString(id: SecurityServerId): string {
  return `SERVER:${shortString([id.xRoadInstance, id.memberClass, id.memberCode, id.serverCode])}`;
}
