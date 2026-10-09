<script lang="ts">
  // Small stroke icons (inline SVG, no external assets).
  type Name = 'check' | 'warn' | 'x' | 'info' | 'upload' | 'file' | 'download' | 'refresh' | 'shield' | 'clock';
  let { name, size = 20 }: { name: Name; size?: number } = $props();
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="2"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
  focusable="false"
>
  {#if name === 'check'}
    <circle cx="12" cy="12" r="9.5" /><path d="m7.5 12.5 3 3 6-6.5" />
  {:else if name === 'warn'}
    <path d="M10.3 3.9 2.4 17.6A2 2 0 0 0 4.1 20.6h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /><path
      d="M12 9.5v4.5"
    /><path d="M12 17.2h.01" />
  {:else if name === 'x'}
    <circle cx="12" cy="12" r="9.5" /><path d="m15 9-6 6M9 9l6 6" />
  {:else if name === 'info'}
    <circle cx="12" cy="12" r="9.5" /><path d="M12 11v5.5" /><path d="M12 7.8h.01" />
  {:else if name === 'upload'}
    <path d="M12 15V4" /><path d="m7 8.5 5-5 5 5" /><path d="M4 15v3.5A2.5 2.5 0 0 0 6.5 21h11a2.5 2.5 0 0 0 2.5-2.5V15" />
  {:else if name === 'file'}
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" /><path d="M14 3v5h5" />
  {:else if name === 'download'}
    <path d="M12 4v11" /><path d="m7 10.5 5 5 5-5" /><path d="M4 20h16" />
  {:else if name === 'refresh'}
    <path d="M20 11a8 8 0 0 0-14.3-4.9L4 8" /><path d="M4 3.5V8h4.5" /><path d="M4 13a8 8 0 0 0 14.3 4.9L20 16" /><path
      d="M20 20.5V16h-4.5"
    />
  {:else if name === 'shield'}
    <path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6Z" />
  {:else if name === 'clock'}
    <circle cx="12" cy="12" r="9.5" /><path d="M12 7v5l3 2" />
  {/if}
</svg>
