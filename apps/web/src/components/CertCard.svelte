<script lang="ts">
  import type { CertSummary } from '@xrav/verifier';
  import { commonName, fmtUtc } from '../lib/format';

  let {
    role,
    cert,
    facts = [],
  }: { role: string; cert: CertSummary; facts?: { label: string; value: string; mono?: boolean }[] } = $props();
</script>

<article class="card cert">
  <h3 class="section-title">{role}</h3>
  <p class="cn wrap-any">{commonName(cert.subject)}</p>

  {#if facts.length}
    <dl class="facts primary">
      {#each facts as f (f.label)}
        <div>
          <dt>{f.label}</dt>
          <dd class:mono={f.mono} class="wrap-any">{f.value}</dd>
        </div>
      {/each}
    </dl>
  {/if}

  <dl class="facts">
    <div>
      <dt>Subject</dt>
      <dd class="mono wrap-any">{cert.subject}</dd>
    </div>
    <div>
      <dt>Issuer</dt>
      <dd class="mono wrap-any">{cert.issuer}</dd>
    </div>
    <div class="row">
      <div>
        <dt>Serial number</dt>
        <dd class="mono wrap-any">{cert.serialNumber}</dd>
      </div>
      <div>
        <dt>Valid from</dt>
        <dd><span class="nw">{fmtUtc(cert.notBefore)}</span><span class="until"><span class="to">until</span> <span class="nw">{fmtUtc(cert.notAfter)}</span></span></dd>
      </div>
    </div>
  </dl>
</article>

<style>
  .cert {
    padding: 1rem 1.1rem;
    min-width: 0;
  }
  .section-title {
    margin-bottom: 0.25rem;
  }
  .cn {
    margin: 0 0 0.75rem;
    font-weight: 600;
    font-size: 1.0625rem;
  }
  .facts {
    margin: 0;
    display: grid;
    gap: 0.55rem;
  }
  .facts.primary {
    padding-bottom: 0.75rem;
    margin-bottom: 0.75rem;
    border-bottom: 1px solid var(--border);
  }
  .row {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 1.25rem;
  }
  dt {
    font-size: 0.75rem;
    color: var(--text-3);
    font-weight: 500;
  }
  dd {
    margin: 0.1rem 0 0;
    font-size: 0.9rem;
  }
  .nw {
    white-space: nowrap;
  }
  .until {
    display: block;
  }
  .to {
    color: var(--text-3);
    font-size: 0.8125rem;
  }
</style>
