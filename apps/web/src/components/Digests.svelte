<script lang="ts">
  import { type AttachmentFile, type DigestStatus, digestStatus } from '../lib/messageView';
  import { groupHex } from '../lib/format';
  import Icon from './Icon.svelte';

  let {
    digests,
    attachments,
  }: {
    digests: { uri: string; digestHex: string; verified: boolean }[];
    attachments: readonly AttachmentFile[] | null;
  } = $props();

  const LABEL: Record<DigestStatus, string> = {
    verified: 'Attachment matches the signed digest',
    mismatch: 'Attachment content does not match the signed digest',
    absent: 'Digest signed; attachment not included in container',
    unknown: 'Not verified (container contents unavailable)',
  };
</script>

<section class="card digests" aria-labelledby="digests-title">
  <h3 id="digests-title" class="section-title">Signed attachment digests (SHA-512)</h3>
  {#if digests.length === 0}
    <p class="empty">No attachment digests: the signature does not cover any attachments.</p>
  {:else}
    <ul>
      {#each digests as d, i (i)}
        {@const s = digestStatus(d, attachments)}
        <li class="st-{s}">
          <div class="top">
            <span class="uri mono wrap-any">{d.uri}</span>
            <span class="badge"
              ><Icon name={s === 'verified' ? 'check' : s === 'absent' ? 'info' : 'warn'} size={14} />{LABEL[s]}</span
            >
          </div>
          <code class="hex wrap-any">{groupHex(d.digestHex)}</code>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .digests {
    padding: 1rem 1.1rem;
  }
  .empty {
    margin: 0;
    color: var(--text-2);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 0.6rem;
  }
  li {
    padding: 0.6rem 0.75rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--surface-2);
  }
  .st-verified {
    --tone: var(--ok);
    --tone-bg: var(--ok-bg);
    --tone-border: var(--ok-border);
  }
  .st-mismatch,
  .st-unknown {
    --tone: var(--warn);
    --tone-bg: var(--warn-bg);
    --tone-border: var(--warn-border);
  }
  .st-absent {
    --tone: var(--idle);
    --tone-bg: var(--idle-bg);
    --tone-border: var(--idle-border);
  }
  .st-mismatch {
    background: var(--warn-bg);
    border-color: var(--warn-border);
    border-left: 4px solid var(--warn);
  }
  .top {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 0.35rem 0.75rem;
    align-items: center;
    margin-bottom: 0.35rem;
  }
  .uri {
    font-weight: 600;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.8125rem;
    font-weight: 600;
    color: var(--tone);
    background: var(--tone-bg);
    border: 1px solid var(--tone-border);
    padding: 0.05rem 0.5rem;
    border-radius: 999px;
  }
  .hex {
    display: block;
    color: var(--text-2);
    font-size: 0.8rem;
    line-height: 1.6;
  }
</style>
