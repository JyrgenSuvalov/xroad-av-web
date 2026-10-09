<script lang="ts">
  // Attachments are offered ONLY as downloads: an application/octet-stream
  // Blob URL with a download attribute, never rendered inline.
  import { fmtBytes, safeFileName } from '../lib/format';
  import type { AttachmentFile } from '../lib/messageView';
  import Icon from './Icon.svelte';

  let { file }: { file: AttachmentFile } = $props();

  let url = $state<string | null>(null);

  $effect(() => {
    const u = URL.createObjectURL(new Blob([new Uint8Array(file.bytes)], { type: 'application/octet-stream' }));
    url = u;
    return () => URL.revokeObjectURL(u);
  });
</script>

<a class="btn dl" href={url ?? undefined} download={safeFileName(file.name)} rel="noopener">
  <Icon name="download" size={16} />
  <span class="mono wrap-any">{file.name}</span>
  <span class="size">{fmtBytes(file.bytes.length)}</span>
</a>

<style>
  .dl {
    max-width: 100%;
  }
  .size {
    color: var(--text-3);
    font-size: 0.8125rem;
  }
</style>
