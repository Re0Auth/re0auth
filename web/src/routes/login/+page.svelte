<script lang="ts">
	import { onMount } from 'svelte';
	import { ArrowRight, ExternalLink } from 'lucide-svelte';
	import AuthShell from '#lib/components/AuthShell.svelte';
	import { readQuery, startLogin } from '#lib/api.ts';

	let returnTo = $state('/');

	onMount(() => {
		returnTo = readQuery('return_to') || '/';
	});

	function login(): void {
		startLogin(returnTo);
	}
</script>

<AuthShell
	title="登录 Re0Auth"
	subtitle="使用外部身份提供商完成登录。Re0Auth 不保存你的密码。"
>
	<div class="auth-actions">
		<button class="btn-primary" type="button" onclick={login}>
			继续登录
			<ArrowRight size={16} aria-hidden="true" />
		</button>
	</div>
	<p class="meta">
		<ExternalLink size={13} aria-hidden="true" />
		登录过程会离开 Re0Auth，由外部 IdP 完成身份校验。
	</p>
</AuthShell>
