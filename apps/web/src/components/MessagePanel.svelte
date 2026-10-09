<script lang="ts">
  // All values are untrusted container data: rendered as text only (no {@html}).
  import { fmtBytes } from '../lib/format';
  import type { MessageView, MessageViewResult } from '../lib/messageView';
  import DownloadLink from './DownloadLink.svelte';
  import Icon from './Icon.svelte';

  let { message }: { message: MessageViewResult } = $props();

  const KIND = { soap: 'SOAP', 'rest-request': 'REST request', 'rest-response': 'REST response', unknown: 'Unparsed' };
  const kindLabel = (v: MessageView) => (v.kind === 'soap' && v.direction ? `SOAP ${v.direction}` : KIND[v.kind]);
</script>

<section class="card message" aria-labelledby="message-title">
  <div class="head">
    <h2 id="message-title" class="section-title">Message</h2>
    {#if message.status === 'ok'}<span class="kind">{kindLabel(message.view)}</span>{/if}
  </div>

  {#if message.status !== 'ok'}
    <p class="note"><Icon name="info" size={16} />{message.message}</p>
  {:else}
    {@const v = message.view}
    {#if v.restLine}
      <p class="restline mono wrap-any">{v.restLine}</p>
    {/if}
    {#if v.fields.length}
      <dl class="fields">
        {#each v.fields as f, i (i)}
          <dt>{f.label}</dt>
          <dd class="mono wrap-any">{f.value}</dd>
        {/each}
      </dl>
    {/if}

    <details class="raw">
      <summary>
        {v.kind === 'soap' ? 'message.xml' : 'message.xml (REST message)'}
        <span class="muted">{fmtBytes(new TextEncoder().encode(v.rawMessage).length)}</span>
      </summary>
      <pre class="wrap-any">{v.rawMessage}</pre>
    </details>

    <h3 class="sub-title">Attachments</h3>
    {#if v.attachments.length === 0}
      <p class="muted none">This container holds no attachments.</p>
    {:else}
      <p class="muted none">Downloads only. Attachments are never opened in this page.</p>
      <ul class="files">
        {#each v.attachments as a (a.name)}
          <li><DownloadLink file={a} /></li>
        {/each}
      </ul>
    {/if}
  {/if}
</section>

<style>
  .message {
    padding: 1rem 1.1rem 1.1rem;
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 0.5rem;
  }
  .kind {
    font-size: 0.8125rem;
    color: var(--text-2);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 0.05rem 0.6rem;
  }
  .note {
    margin: 0;
    color: var(--text-2);
    display: flex;
    gap: 0.4rem;
    align-items: center;
  }
  .restline {
    margin: 0 0 0.75rem;
    padding: 0.4rem 0.6rem;
    border-radius: var(--radius-sm);
    background: var(--surface-2);
    font-weight: 600;
    font-size: 0.95rem;
  }
  .fields {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.4rem 1.25rem;
    margin: 0 0 1rem;
  }
  .fields dt {
    color: var(--text-3);
    font-size: 0.875rem;
  }
  .fields dd {
    margin: 0;
    min-width: 0;
  }
  @media (max-width: 480px) {
    .fields {
      grid-template-columns: 1fr;
      gap: 0.1rem;
    }
    .fields dd {
      margin-bottom: 0.5rem;
    }
  }

  .raw {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface-2);
  }
  .raw summary {
    cursor: pointer;
    padding: 0.5rem 0.75rem;
    font-family: var(--mono);
    font-size: 0.875rem;
    font-weight: 600;
  }
  .raw summary .muted {
    white-space: nowrap;
  }
  .raw pre {
    margin: 0;
    padding: 0.75rem;
    border-top: 1px solid var(--border);
    white-space: pre-wrap;
    max-height: 28rem;
    overflow: auto;
    font-size: 0.8rem;
    line-height: 1.55;
  }
  .muted {
    color: var(--text-3);
    font-weight: 400;
    font-family: var(--font);
    font-size: 0.8125rem;
    margin-left: 0.4rem;
  }
  .sub-title {
    margin: 1.1rem 0 0.25rem;
    font-size: 0.9375rem;
  }
  .none {
    margin: 0 0 0.5rem;
  }
  .files {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
</style>
