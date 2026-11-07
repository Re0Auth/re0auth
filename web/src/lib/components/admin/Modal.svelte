<script lang="ts">
	import type { Snippet } from 'svelte';

	// 原生 <dialog> 已提供焦点陷阱、滚动锁定与 Esc 取消，
	// 不再引入组件库；Esc 与点遮罩都走同一个关闭回调。
	let {
		open = $bindable(false),
		title,
		description,
		children
	}: {
		open?: boolean;
		title: string;
		description?: string;
		children: Snippet;
	} = $props();

	let element = $state<HTMLDialogElement | null>(null);

	$effect(() => {
		const dialog = element;
		if (!dialog) return;
		if (open && !dialog.open) dialog.showModal();
		if (!open && dialog.open) dialog.close();
	});

	function close(): void {
		open = false;
	}
</script>

<dialog
	bind:this={element}
	oncancel={(event) => {
		event.preventDefault();
		close();
	}}
	onclick={(event) => {
		if (event.target === element) close();
	}}
	class="m-auto w-full max-w-xl rounded-md border border-border bg-bg p-0 text-fg backdrop:bg-black/50"
>
	<div class="max-h-[80vh] overflow-y-auto p-6">
		<h2 class="text-lg font-semibold">{title}</h2>
		{#if description}
			<p class="mt-1 text-sm text-fg-2">{description}</p>
		{/if}
		<div class="mt-4">
			{@render children()}
		</div>
	</div>
</dialog>
