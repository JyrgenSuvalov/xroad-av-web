<script lang="ts">
  import { type VerificationResult, verifyContainer } from '@xrav/verifier';
  import CertCard from './components/CertCard.svelte';
  import Digests from './components/Digests.svelte';
  import DropZone from './components/DropZone.svelte';
  import MessagePanel from './components/MessagePanel.svelte';
  import TrustPanel from './components/TrustPanel.svelte';
  import Verdict from './components/Verdict.svelte';
  import { fmtUtc } from './lib/format';
  import { type MessageViewResult, digestStatus, loadMessageView } from './lib/messageView';
  import { TrustStore, type TrustView } from './lib/trust.svelte';

  /** Dropped-file limit, checked before reading. The core enforces per-entry and total limits. */
  const MAX_BYTES = 64 * 1024 * 1024;

  interface Checked {
    fileName: string;
    size: number;
    result: VerificationResult;
    message: MessageViewResult;
  }

  const store = new TrustStore();

  // DEV-ONLY demo mode (?demo=ok|ok-rest|unverified|fail, ?trust=fresh|stale|failed|none).
  // `import.meta.env.DEV` is false in production builds, so this branch and the
  // demo module are dropped from the bundle.
  let demoTrust = $state.raw<((now: Date) => TrustView | null) | null>(null);

  let checked = $state.raw<Checked | null>(null);
  let busy = $state(false);
  let runError = $state<string | null>(null);

  const trustView = $derived(demoTrust?.(store.now) ?? store.view);
  const enabled = $derived(demoTrust ? trustView.status === 'fresh' || trustView.status === 'stale' : store.trust !== null);

  $effect(() => {
    store.start();
    if (import.meta.env.DEV) {
      const params = new URLSearchParams(location.search);
      const demoKind = params.get('demo');
      const trustKind = params.get('trust');
      if (demoKind || trustKind) {
        void import('./lib/demo').then((demo) => {
          const c = demo.demoCase(demoKind);
          if (c) checked = c;
          if (demo.demoTrust(trustKind, new Date())) demoTrust = (now) => demo.demoTrust(trustKind, now);
        });
      }
    }
    return () => store.stop();
  });

  async function onFile(file: File) {
    const trust = store.trust;
    if (!trust) return;
    busy = true;
    runError = null;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const [result, message] = await Promise.all([
        verifyContainer(bytes, trust),
        loadMessageView(bytes).catch(
          (e: unknown): MessageViewResult => ({ status: 'error', message: e instanceof Error ? e.message : String(e) }),
        ),
      ]);
      checked = { fileName: file.name, size: file.size, result, message };
    } catch (e) {
      checked = null;
      runError = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  const attachments = $derived(checked?.message.status === 'ok' ? checked.message.view.attachments : null);
  const counts = $derived.by(() => {
    const r = checked?.result;
    let mismatched = 0;
    let unconfirmed = 0;
    if (r?.ok) {
      for (const d of r.attachmentDigests) {
        const s = digestStatus(d, attachments);
        if (s === 'mismatch') mismatched++;
        else if (s === 'unknown') unconfirmed++;
      }
    }
    return { mismatched, unconfirmed };
  });

  // Keep a stray drop outside the zone from navigating the page to the file.
  function swallow(e: DragEvent) {
    e.preventDefault();
  }
</script>

<svelte:window ondragover={swallow} ondrop={swallow} />

<div class="page">
  <header class="masthead">
    <h1>X-Road ASiC Verifier</h1>
    <p class="tagline">
      Check signed X-Road message log containers (<span class="mono">.asice</span>) in your browser, against the live
      global configuration. Files never leave this page.
    </p>
  </header>

  <main>
    <TrustPanel view={trustView} now={store.now} onRefresh={() => store.refresh()} simulated={demoTrust !== null} />

    <DropZone disabled={!enabled} {busy} maxBytes={MAX_BYTES} {onFile} />

    {#if runError}
      <p class="run-error card" role="alert">Could not read the file: {runError}</p>
    {/if}

    {#if checked}
      {@const r = checked.result}
      <section class="results" aria-label="Verification result">
        <Verdict
          result={r}
          fileName={checked.fileName}
          fileSize={checked.size}
          mismatched={counts.mismatched}
          unconfirmed={counts.unconfirmed}
        />

        {#if r.ok}
          <div class="certs">
            <CertCard role="Signer" cert={r.signer.cert} facts={[{ label: 'Signer ID', value: r.signer.id, mono: true }]} />
            <CertCard
              role="OCSP responder"
              cert={r.ocsp.signedBy}
              facts={[{ label: 'Response produced at', value: fmtUtc(r.ocsp.producedAt) }]}
            />
            <CertCard
              role="Timestamp authority"
              cert={r.timestamp.signedBy}
              facts={[{ label: 'Timestamp (genTime)', value: fmtUtc(r.timestamp.genTime) }]}
            />
          </div>
          <Digests digests={r.attachmentDigests} {attachments} />
        {/if}

        <MessagePanel message={checked.message} />
      </section>
    {/if}
  </main>
</div>

<style>
  .page {
    max-width: 1040px;
    margin: 0 auto;
    padding: 2rem 1.25rem 3rem;
  }
  .masthead {
    margin-bottom: 1.5rem;
  }
  h1 {
    font-size: clamp(1.5rem, 4vw, 2rem);
    font-weight: 700;
    letter-spacing: -0.015em;
  }
  .tagline {
    margin: 0.4rem 0 0;
    color: var(--text-2);
    max-width: 44rem;
  }
  main {
    display: grid;
    gap: 1.25rem;
  }
  .results {
    display: grid;
    gap: 1.25rem;
    margin-top: 0.5rem;
  }
  .certs {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
    gap: 1rem;
  }
  .run-error {
    margin: 0;
    padding: 0.75rem 1rem;
    color: var(--bad);
    border-color: var(--bad-border);
    overflow-wrap: anywhere;
  }
  @media (max-width: 480px) {
    .page {
      padding: 1.25rem 0.75rem 2rem;
    }
    .certs {
      grid-template-columns: 1fr;
    }
  }
</style>
