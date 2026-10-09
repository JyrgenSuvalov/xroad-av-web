// SharedParams → TrustContext.

import type { ApprovedCa, InstanceTrust, TrustContext, TrustedCert } from '../types';
import { parseCertificate } from './crypto';
import type { CaInfo, SharedParams } from './sharedParams';

export function toTrustedCert(der: Uint8Array): TrustedCert {
  const cert = parseCertificate(der);
  return { der, subjectDer: new Uint8Array(cert.subject.toSchema().toBER(false)), cert };
}

export interface InstanceTrustInput {
  sharedParams: SharedParams;
  confVersion: string;
  /** Directory Expire-date; null = never expires (snapshot without metadata). */
  expiresAt: Date | null;
}

export function instanceTrust({ sharedParams: sp, confVersion, expiresAt }: InstanceTrustInput): InstanceTrust {
  const approvedCas: ApprovedCa[] = [];
  for (const ca of sp.approvedCAs) {
    // Same flattening as SharedParametersCache: topCA then intermediates, per approvedCA.
    for (const info of [ca.topCA, ...ca.intermediateCAs] as CaInfo[]) {
      approvedCas.push({
        cert: toTrustedCert(info.cert),
        certificateProfileInfo: ca.certificateProfileInfo,
        caName: ca.name,
        authenticationOnly: ca.authenticationOnly,
        ocspResponderCerts: info.ocsp.flatMap((o) => (o.cert ? [toTrustedCert(o.cert)] : [])),
        ocspUrls: info.ocsp.map((o) => o.url),
      });
    }
  }
  return {
    instanceId: sp.instanceIdentifier,
    confVersion,
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
    approvedCas,
    tsaCerts: sp.approvedTSAs.map((t) => toTrustedCert(t.cert)),
    ocspFreshnessSeconds: sp.globalSettings.ocspFreshnessSeconds,
  };
}

export interface TrustContextInput {
  /** Main instance identifier (anchor / instance-identifier file). */
  mainInstance: string;
  instances: InstanceTrust[];
  verifyOcspNextUpdate?: boolean;
}

export function buildTrustContext(input: TrustContextInput): TrustContext {
  const main = input.instances.find((i) => i.instanceId === input.mainInstance);
  if (!main) throw new Error(`main instance ${input.mainInstance} has no shared-params`);
  const instances = [main, ...input.instances.filter((i) => i !== main)];
  return {
    mainInstance: input.mainInstance,
    confVersion: main.confVersion,
    verifyOcspNextUpdate: input.verifyOcspNextUpdate ?? true,
    visibleInstances: (now: Date) =>
      instances.filter(
        (i) => i === main || i.expiresAt === null || Date.parse(i.expiresAt) > now.getTime(),
      ),
  };
}
