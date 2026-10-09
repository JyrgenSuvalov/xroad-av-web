<script lang="ts">
  import { fmtBytes } from '../lib/format';
  import Icon from './Icon.svelte';

  let {
    disabled,
    busy,
    maxBytes,
    onFile,
  }: { disabled: boolean; busy: boolean; maxBytes: number; onFile: (file: File) => void } = $props();

  let input: HTMLInputElement | undefined = $state();
  let dragging = $state(false);
  let problem = $state<string | null>(null);

  const inactive = $derived(disabled || busy);

  function accept(files: FileList | null | undefined) {
    problem = null;
    if (!files || files.length === 0) return;
    if (files.length > 1) {
      problem = 'Drop one container at a time.';
      return;
    }
    const file = files[0]!;
    if (!/\.asice$/i.test(file.name)) {
      problem = `“${file.name}” is not an .asice container.`;
      return;
    }
    // Checked before reading anything.
    if (file.size > maxBytes) {
      problem = `“${file.name}” is ${fmtBytes(file.size)}; the limit is ${fmtBytes(maxBytes)}.`;
      return;
    }
    onFile(file);
  }

  function ondragover(e: DragEvent) {
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = inactive ? 'none' : 'copy';
    dragging = !inactive;
  }

  function ondrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    if (inactive) return;
    accept(e.dataTransfer?.files);
  }

  function onchange() {
    accept(input?.files);
    // Allow choosing the same file again.
    if (input) input.value = '';
  }
</script>

<div
  class="zone"
  class:dragging
  class:disabled={inactive}
  role="group"
  aria-labelledby="drop-title"
  aria-describedby="drop-hint"
  {ondragover}
  ondragenter={ondragover}
  ondragleave={() => (dragging = false)}
  {ondrop}
>
  <span class="glyph" class:spin={busy}><Icon name={busy ? 'refresh' : 'upload'} size={28} /></span>
  <p id="drop-title" class="title">
    {#if busy}
      Verifying…
    {:else if disabled}
      Verification unavailable
    {:else}
      Drop an <span class="mono">.asice</span> container here
    {/if}
  </p>
  <p id="drop-hint" class="hint">
    {#if disabled}
      A trusted global configuration is needed first. See the status above.
    {:else}
      One file at a time, up to {fmtBytes(maxBytes)}. It is checked in this browser and is not uploaded anywhere.
    {/if}
  </p>
  <button class="btn btn-primary" type="button" disabled={inactive} onclick={() => input?.click()}>
    <Icon name="file" size={16} />Choose file…
  </button>
  <input
    bind:this={input}
    class="visually-hidden"
    type="file"
    accept=".asice,application/vnd.etsi.asic-e+zip"
    tabindex="-1"
    aria-hidden="true"
    disabled={inactive}
    {onchange}
  />
  {#if problem}
    <p class="problem" role="alert"><Icon name="warn" size={16} />{problem}</p>
  {/if}
</div>

<style>
  .zone {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 0.4rem;
    padding: 1.75rem 1.25rem;
    border: 2px dashed var(--border-strong);
    border-radius: var(--radius);
    background: var(--surface);
  }
  .zone.dragging {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .zone.disabled {
    background: var(--surface-2);
  }
  .glyph {
    color: var(--accent);
    display: inline-flex;
  }
  .disabled .glyph {
    color: var(--text-3);
  }
  .title {
    margin: 0.25rem 0 0;
    font-size: 1.125rem;
    font-weight: 600;
  }
  .hint {
    margin: 0 0 0.6rem;
    color: var(--text-2);
    font-size: 0.9375rem;
    max-width: 36rem;
  }
  .problem {
    display: inline-flex;
    gap: 0.4rem;
    align-items: center;
    margin: 0.6rem 0 0;
    color: var(--warn);
    font-weight: 500;
    overflow-wrap: anywhere;
  }
</style>
