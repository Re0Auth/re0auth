<script lang="ts">
	import { ArrowRight } from 'lucide-svelte';
	import DocLayout from '#lib/components/layouts/DocLayout.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import AboutBody from '../../content/about.md';
</script>

<DocLayout title="关于 Re0Auth">
	<AboutBody />
	<div class="auth-actions not-prose">
		<Button class="h-11 w-full rounded-sm" href="/account">
			账号与授权
			<ArrowRight size={16} aria-hidden="true" />
		</Button>
		<Button variant="outline" class="h-11 w-full rounded-sm" href="/">返回</Button>
	</div>
</DocLayout>
