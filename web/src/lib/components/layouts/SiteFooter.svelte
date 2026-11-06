<script lang="ts">
	import { KeyRound } from 'lucide-svelte';
</script>

<footer class="border-t border-border">
	<div
		class="mx-auto flex max-w-5xl flex-col gap-4 px-4 py-8 text-sm text-fg-3 sm:flex-row sm:items-center sm:justify-between"
	>
		<div class="flex items-center gap-2">
			<KeyRound size={14} strokeWidth={1.8} aria-hidden="true" />
			<span>Re0Auth · 音游数据的授权中间层</span>
		</div>
		<div class="flex gap-4">
			<a class="transition-colors hover:text-fg" href="/about">关于</a>
			<a class="transition-colors hover:text-fg" href="/device">批准设备</a>
			<a class="transition-colors hover:text-fg" href="/login">登录</a>
		</div>
	</div>
</footer>
