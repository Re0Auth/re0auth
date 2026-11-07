<script lang="ts">
	import { ArrowRight } from 'lucide-svelte';
	import DocLayout from '#lib/components/layouts/DocLayout.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import AboutBody from '../../content/about.md';
	import { copy } from '#lib/copy.ts';
</script>

<DocLayout title={copy.about.title}>
	<AboutBody />
	<div class="auth-actions not-prose">
		<Button class="h-11 w-full rounded-sm" href="/account">
			{copy.about.account}
			<ArrowRight size={16} aria-hidden="true" />
		</Button>
		<Button variant="outline" class="h-11 w-full rounded-sm" href="/">{copy.common.back}</Button>
	</div>
</DocLayout>
