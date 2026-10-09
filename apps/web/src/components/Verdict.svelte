<script lang="ts">
  import type { VerificationResult } from '@xrav/verifier';
  import { fmtBytes } from '../lib/format';
  import Icon from './Icon.svelte';

  let {
    result,
    fileName,
    fileSize,
    mismatched,
    unconfirmed,
  }: {
    result: VerificationResult;
    fileName: string;
    fileSize: number;
    /** Attachments present in the container whose bytes do not match the signed digest. */
    mismatched: number;
    /** Unverified digests whose attachment presence is unknown (message view unavailable). */
    unconfirmed: number;
  } = $props();

  const tone = $derived(!result.ok ? 'bad' : mismatched > 0 || unconfirmed > 0 ? 'warn' : 'ok');
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
</script>

<section class="verdict tone-{tone}" role="status" aria-live="polite" aria-atomic="true">
  <span class="icon"><Icon name={tone === 'ok' ? 'check' : tone === 'warn' ? 'warn' : 'x'} size={44} /></span>
  <div class="body">
    {#if result.ok}
      <p class="big">Signature valid</p>
      {#if mismatched > 0}
        <p class="sub">
          <strong>But the content of {plural(mismatched, 'attachment does', 'attachments do')} not match the signed digest.</strong>
          X-Road still reports success for batch-signed containers. Treat that attachment content as modified.
        </p>
      {:else if unconfirmed > 0}
        <p class="sub">
          <strong>{plural(unconfirmed, 'attachment digest was', 'attachment digests were')} not verified</strong>
          against attachment contents.
        </p>
      {:else}
        <p class="sub">Signature, timestamp and OCSP response check out against the trusted configuration.</p>
      {/if}
    {:else}
      <p class="big">Verification failed</p>
      <p class="fault"><code class="wrap-any">{result.faultCode}</code></p>
      <p class="sub wrap-any">{result.faultString}</p>
    {/if}
    <p class="meta">
      <span class="wrap-any"><Icon name="file" size={14} /> {fileName}</span>
      <span>{fmtBytes(fileSize)}</span>
    </p>
  </div>
</section>

<style>
  .verdict {
    display: flex;
    gap: 1rem;
    align-items: flex-start;
    padding: 1.25rem 1.4rem;
    border-radius: var(--radius);
    background: var(--tone-bg);
    border: 1px solid var(--tone-border);
    border-left: 6px solid var(--tone);
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
  .icon {
    color: var(--tone);
    display: inline-flex;
    flex: none;
  }
  .body {
    min-width: 0;
    flex: 1;
  }
  .big {
    margin: 0;
    font-size: clamp(1.6rem, 5vw, 2.25rem);
    font-weight: 700;
    line-height: 1.15;
    color: var(--tone);
    letter-spacing: -0.01em;
  }
  .sub {
    margin: 0.4rem 0 0;
    color: var(--text);
    max-width: 46rem;
  }
  .fault {
    margin: 0.5rem 0 0;
  }
  .fault code {
    font-size: 1.05rem;
    font-weight: 600;
    padding: 0.15rem 0.5rem;
    border-radius: var(--radius-sm);
    background: var(--surface);
    border: 1px solid var(--tone-border);
    color: var(--tone);
  }
  .meta {
    margin: 0.85rem 0 0;
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem 1.1rem;
    color: var(--text-2);
    font-size: 0.875rem;
  }
  .meta :global(svg) {
    vertical-align: -2px;
  }

  @media (max-width: 480px) {
    .verdict {
      flex-direction: column;
      gap: 0.5rem;
      padding: 1rem;
    }
  }
</style>
