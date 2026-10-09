// 60 s configuration polling state machine
//
//   none    no verified configuration yet (verification disabled)
//   fresh   verified configuration, now ≤ Expire-date, last refresh OK (green)
//   stale   verified configuration kept, but expired and/or the last refresh
//           failed (fetch error, malformed, rollback) — amber, still usable
//   failed  signature / anchor / tamper failure (HARD_FAILURE_CODES) — red,
//           verification disabled, even if an earlier configuration was good.
//           Also a malformed directory when nothing good was ever loaded.
//
// Recovery: a later refresh that fully verifies (and is not a rollback)
// returns to fresh. Every accepted configuration is anchor-signed, so this
// does not weaken the hard-fail rule; it avoids requiring a page reload after
// a transient proxy fault.

import type { TrustContext } from '../types';
import { GlobalConfError } from './errors';

export type PollerStatus = 'none' | 'fresh' | 'stale' | 'failed';

export interface PollerError {
  code: string;
  message: string;
  at: Date;
}

export interface PolledConf {
  expireDate: Date;
  trust: TrustContext;
}

export interface PollerState<C extends PolledConf> {
  status: PollerStatus;
  /** Configuration to verify against: set only for fresh/stale. */
  conf: C | null;
  /** Last accepted configuration (kept in `failed` for display / anti-rollback). */
  lastGood: C | null;
  /** Current configuration is past its Expire-date (stale reason). */
  expired: boolean;
  /** Error of the last refresh (stale reason), or the hard failure (failed). */
  error: PollerError | null;
  lastAttempt: Date | null;
  lastSuccess: Date | null;
}

export interface TimerLike {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface ConfPollerOptions<C extends PolledConf> {
  load: () => Promise<C>;
  intervalMs?: number;
  clock?: () => Date;
  timer?: TimerLike;
}

const defaultTimer: TimerLike = {
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (h) => globalThis.clearTimeout(h as ReturnType<typeof globalThis.setTimeout>),
};

function toPollerError(e: unknown, at: Date): PollerError {
  if (e instanceof GlobalConfError) return { code: e.code, message: e.message, at };
  return { code: 'FETCH_FAILED', message: e instanceof Error ? e.message : String(e), at };
}

export class ConfPoller<C extends PolledConf> {
  private readonly load: () => Promise<C>;
  private readonly intervalMs: number;
  private readonly clock: () => Date;
  private readonly timer: TimerLike;

  private current: C | null = null;
  private refreshError: PollerError | null = null;
  private hardError: PollerError | null = null;
  private lastAttempt: Date | null = null;
  private lastSuccess: Date | null = null;
  private handle: unknown = null;
  private running = false;
  private inflight: Promise<PollerState<C>> | null = null;
  private readonly listeners = new Set<(s: PollerState<C>) => void>();

  constructor(options: ConfPollerOptions<C>) {
    this.load = options.load;
    this.intervalMs = options.intervalMs ?? 60_000;
    this.clock = options.clock ?? (() => new Date());
    this.timer = options.timer ?? defaultTimer;
  }

  /** State derived against the clock, so expiry turns amber without a refresh. */
  get state(): PollerState<C> {
    const now = this.clock();
    const expired = this.current !== null && now.getTime() > this.current.expireDate.getTime();
    let status: PollerStatus;
    if (this.hardError) status = 'failed';
    else if (!this.current) status = 'none';
    else status = expired || this.refreshError ? 'stale' : 'fresh';
    const usable = status === 'fresh' || status === 'stale';
    return {
      status,
      conf: usable ? this.current : null,
      lastGood: this.current,
      expired,
      error: this.hardError ?? this.refreshError,
      lastAttempt: this.lastAttempt,
      lastSuccess: this.lastSuccess,
    };
  }

  /** TrustContext to verify against, or null when verification is disabled. */
  get trust(): TrustContext | null {
    return this.state.conf?.trust ?? null;
  }

  subscribe(listener: (s: PollerState<C>) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Load now, then every intervalMs after each completed attempt. */
  start(): Promise<PollerState<C>> {
    this.running = true;
    return this.tick();
  }

  stop(): void {
    this.running = false;
    if (this.handle !== null) this.timer.clearTimeout(this.handle);
    this.handle = null;
  }

  /** One refresh; concurrent callers share the in-flight attempt. */
  refresh(): Promise<PollerState<C>> {
    this.inflight ??= this.doRefresh().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async tick(): Promise<PollerState<C>> {
    if (this.handle !== null) this.timer.clearTimeout(this.handle);
    this.handle = null;
    const s = await this.refresh();
    if (this.running) this.handle = this.timer.setTimeout(() => void this.tick(), this.intervalMs);
    return s;
  }

  private async doRefresh(): Promise<PollerState<C>> {
    this.lastAttempt = this.clock();
    try {
      const conf = await this.load();
      this.accept(conf);
    } catch (e) {
      this.reject(e);
    }
    const s = this.state;
    for (const l of this.listeners) l(s);
    return s;
  }

  private accept(conf: C): void {
    const at = this.clock();
    // Anti-rollback: never replace with an older Expire-date.
    if (this.current && conf.expireDate.getTime() < this.current.expireDate.getTime()) {
      this.refreshError = {
        code: 'ROLLBACK',
        message: `ROLLBACK: offered Expire-date ${conf.expireDate.toISOString()} is older than current ${this.current.expireDate.toISOString()}`,
        at,
      };
      return;
    }
    this.current = conf;
    this.refreshError = null;
    this.hardError = null;
    this.lastSuccess = at;
  }

  private reject(e: unknown): void {
    const err = toPollerError(e, this.clock());
    const hard =
      (e instanceof GlobalConfError && e.hard) ||
      // Nothing good ever loaded: a malformed/unparseable configuration is fatal.
      (!this.current && (err.code === 'DIRECTORY_MALFORMED' || err.code === 'SHARED_PARAMS_INVALID'));
    if (hard) this.hardError = err;
    else if (!this.hardError) this.refreshError = err;
  }
}
