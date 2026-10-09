<script lang="ts">
  import { fmtClock, fmtRelative, fmtTime, fmtUtc } from '../lib/format';
  import type { TrustView } from '../lib/trust.svelte';
  import Icon from './Icon.svelte';

  let {
    view,
    now,
    onRefresh,
    simulated = false,
  }: { view: TrustView; now: Date; onRefresh: () => void; simulated?: boolean } = $props();

  type Tone = 'ok' | 'warn' | 'bad' | 'idle';

  const tone: Tone = $derived(
    view.status === 'fresh' ? 'ok' : view.status === 'stale' ? 'warn' : view.status === 'failed' ? 'bad' : 'idle',
  );

  const headline = $derived.by(() => {
    switch (view.status) {
      case 'fresh':
        return 'Trusted configuration loaded';
      case 'stale':
        return view.expired ? 'Configuration expired (last good one kept)' : 'Configuration refresh failing (last good one kept)';
      case 'failed':
        return 'Configuration rejected: verification disabled';
      default:
        return view.loading ? 'Loading configuration…' : 'No configuration: verification disabled';
    }
  });

  const pill = $derived(
    { fresh: 'Fresh', stale: 'Stale', failed: 'Failed', none: view.loading ? 'Loading' : 'None' }[view.status],
  );
</script>

<section class="card trust tone-{tone}" aria-labelledby="trust-title">
  <header class="head">
    <div class="title-row">
      <span class="icon"><Icon name={tone === 'ok' ? 'shield' : tone === 'warn' ? 'warn' : tone === 'bad' ? 'x' : 'clock'} /></span>
      <div>
        <h2 id="trust-title" class="section-title">Global configuration</h2>
        <p class="headline" role="status" aria-live="polite">{headline}</p>
      </div>
    </div>
    <div class="actions">
      {#if simulated}<span class="sim">simulated</span>{/if}
      <span class="pill"><span class="dot"></span>{pill}</span>
      <button class="btn refresh" type="button" onclick={onRefresh} title="Refresh the configuration now">
        <Icon name="refresh" size={16} /><span class="refresh-label">Refresh</span>
      </button>
    </div>
  </header>

  <dl class="facts">
    <div>
      <dt>Instance</dt>
      <dd class="mono wrap-any">{view.instanceId ?? '—'}</dd>
    </div>
    <div>
      <dt>Last refresh</dt>
      <dd>
        {#if view.lastSuccess}
          {fmtTime(view.lastSuccess)}
          <span class="muted block">{fmtRelative(view.lastSuccess, now)}</span>
        {:else}
          —
        {/if}
      </dd>
    </div>
    <div>
      <dt>Expires</dt>
      <dd>
        {#if view.expireDate}
          <span class:expired={view.expired}>{fmtUtc(view.expireDate)}</span>
          <span class="muted block">{view.expired ? 'expired ' : 'expires '}{fmtRelative(view.expireDate, now)}</span>
        {:else}
          —
        {/if}
      </dd>
    </div>
    <div>
      <dt>Local time</dt>
      <dd>{fmtClock(now)}</dd>
    </div>
  </dl>

  {#if view.error}
    <p class="error">
      <code class="code">{view.error.code}</code>
      <span class="wrap-any">{view.error.message}</span>
      <span class="muted">at {fmtTime(view.error.at)}</span>
    </p>
  {/if}
</section>

<style>
  .trust {
    padding: 1rem 1.25rem 1.1rem;
    border-left: 5px solid var(--tone);
  }
  .tone-ok {
    --tone: var(--ok);
    --tone-bg: var(--ok-bg);
    --tone-border: var(--ok-border);
  }
  .tone-warn {
    --tone: var(--warn);
    --tone-bg: var(--warn-bg);
    --tone-border: var(--warn-border);
  }
  .tone-bad {
    --tone: var(--bad);
    --tone-bg: var(--bad-bg);
    --tone-border: var(--bad-border);
  }
  .tone-idle {
    --tone: var(--idle);
    --tone-bg: var(--idle-bg);
    --tone-border: var(--idle-border);
  }

  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    gap: 0.75rem;
  }
  .title-row {
    display: flex;
    gap: 0.75rem;
    align-items: flex-start;
    min-width: 0;
  }
  .icon {
    color: var(--tone);
    margin-top: 0.1rem;
    display: inline-flex;
  }
  .section-title {
    margin: 0 0 0.15rem;
  }
  .headline {
    margin: 0;
    font-weight: 600;
    font-size: 1.0625rem;
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.2rem 0.65rem;
    border-radius: 999px;
    background: var(--tone-bg);
    border: 1px solid var(--tone-border);
    color: var(--tone);
    font-size: 0.8125rem;
    font-weight: 600;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--tone);
  }
  .sim {
    font-size: 0.75rem;
    color: var(--text-3);
    border: 1px dashed var(--border-strong);
    border-radius: 999px;
    padding: 0.1rem 0.5rem;
  }
  .refresh {
    padding: 0.3rem 0.6rem;
    font-size: 0.8125rem;
  }

  /* Fixed tracks: the ticking clock and relative times must not shift their neighbours. */
  .facts {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(13.5rem, 1fr));
    gap: 0.75rem 2rem;
    margin: 1rem 0 0;
  }
  .facts div {
    min-width: 0;
    max-width: 100%;
  }
  dt {
    font-size: 0.75rem;
    color: var(--text-3);
    font-weight: 500;
  }
  dd {
    margin: 0.1rem 0 0;
    font-size: 0.9375rem;
    font-variant-numeric: tabular-nums;
  }
  .muted {
    color: var(--text-3);
    font-size: 0.875rem;
  }
  .block {
    display: block;
  }
  .expired {
    color: var(--warn);
    font-weight: 600;
  }

  .error {
    margin: 1rem 0 0;
    padding: 0.6rem 0.8rem;
    border-radius: var(--radius-sm);
    background: var(--tone-bg);
    border: 1px solid var(--tone-border);
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem 0.6rem;
    align-items: baseline;
    font-size: 0.9375rem;
  }
  .code {
    color: var(--tone);
    font-weight: 600;
  }

  @media (max-width: 480px) {
    .trust {
      padding: 0.9rem 1rem;
    }
    .refresh-label {
      display: none;
    }
  }
</style>
