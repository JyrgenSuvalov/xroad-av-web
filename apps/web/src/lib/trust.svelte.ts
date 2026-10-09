// Reactive wrapper around the verifier's ConfPoller (trust panel).
//
// The anchor is loaded lazily inside `load`, so an unreachable /anchor.xml is
// retried on the next tick like any other refresh failure, and an invalid
// anchor (ANCHOR_INVALID, a hard failure) turns the panel red.

import {
  type ConfigurationAnchor,
  ConfPoller,
  type FetchLike,
  type PollerState,
  type PollerStatus,
  type TrustContext,
  type VerifiedConf,
  fetchVerifiedConf,
  loadAnchor,
} from '@xrav/verifier';

/** What the trust panel renders. Plain data, so demo mode can fake it. */
export interface TrustView {
  status: PollerStatus;
  instanceId: string | null;
  confVersion: string | null;
  expireDate: Date | null;
  expired: boolean;
  lastSuccess: Date | null;
  lastAttempt: Date | null;
  error: { code: string; message: string; at: Date } | null;
  /** True until the first attempt has finished. */
  loading: boolean;
}

export function toTrustView(s: PollerState<VerifiedConf>, loading: boolean): TrustView {
  const conf = s.lastGood;
  return {
    status: s.status,
    instanceId: conf?.instanceIdentifier ?? null,
    confVersion: conf?.confVersion ?? null,
    expireDate: conf?.expireDate ?? null,
    expired: s.expired,
    lastSuccess: s.lastSuccess,
    lastAttempt: s.lastAttempt,
    error: s.error,
    loading,
  };
}

const browserFetch: FetchLike = (url, init) => fetch(url, init);

export class TrustStore {
  view = $state.raw<TrustView>({
    status: 'none',
    instanceId: null,
    confVersion: null,
    expireDate: null,
    expired: false,
    lastSuccess: null,
    lastAttempt: null,
    error: null,
    loading: true,
  });
  /** Current time, ticking each second (expiry countdown, relative times). */
  now = $state.raw(new Date());
  /** TrustContext to verify against; null = verification disabled. */
  trust = $state.raw<TrustContext | null>(null);

  #poller: ConfPoller<VerifiedConf>;
  #anchor: ConfigurationAnchor | null = null;
  #clock: ReturnType<typeof setInterval> | null = null;
  #loading = true;

  constructor() {
    this.#poller = new ConfPoller<VerifiedConf>({
      load: async () => {
        this.#anchor ??= await loadAnchor(browserFetch);
        return fetchVerifiedConf(browserFetch, this.#anchor);
      },
    });
    this.#poller.subscribe(() => {
      this.#loading = false;
      this.#sync();
    });
  }

  start(): void {
    void this.#poller.start();
    this.#clock = setInterval(() => {
      this.now = new Date();
      // Poller state is derived from the clock: expiry turns amber without a refresh.
      this.#sync();
    }, 1000);
  }

  stop(): void {
    this.#poller.stop();
    if (this.#clock !== null) clearInterval(this.#clock);
    this.#clock = null;
  }

  refresh(): void {
    void this.#poller.refresh();
  }

  #sync(): void {
    const s = this.#poller.state;
    this.view = toTrustView(s, this.#loading);
    this.trust = s.conf?.trust ?? null;
  }
}
