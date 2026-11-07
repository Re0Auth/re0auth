<script lang="ts">
	import { onMount } from 'svelte';
	import { ArrowRight, KeyRound, Link2, ShieldCheck, Unplug } from 'lucide-svelte';
	import SiteLayout from '#lib/components/layouts/SiteLayout.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { ApiError, apiGet, meSchema, openLogin, type Me } from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';

	let me = $state<Me | null>(null);
	let checked = $state(false);

	onMount(async () => {
		try {
			me = await apiGet('/api/me', meSchema);
		} catch (cause) {
			// 401 is the ordinary "not signed in" case, not an error to report.
			if (!(cause instanceof ApiError && cause.status === 401)) {
				console.error(cause);
			}
		} finally {
			checked = true;
		}
	});

	function login(): void {
		openLogin('/account');
	}

	const features = [
		{
			icon: Link2,
			title: copy.home.features.ssoTitle,
			body: copy.home.features.ssoBody
		},
		{
			icon: ShieldCheck,
			title: copy.home.features.isolatedTitle,
			body: copy.home.features.isolatedBody
		},
		{
			icon: Unplug,
			title: copy.home.features.mentalTitle,
			body: copy.home.features.mentalBody
		}
	];

	const steps = [
		{ n: '01', title: copy.home.steps.loginTitle, body: copy.home.steps.loginBody },
		{ n: '02', title: copy.home.steps.bindTitle, body: copy.home.steps.bindBody },
		{ n: '03', title: copy.home.steps.consentTitle, body: copy.home.steps.consentBody },
		{ n: '04', title: copy.home.steps.revokeTitle, body: copy.home.steps.revokeBody }
	];
</script>

<SiteLayout>
	<section class="mx-auto max-w-3xl text-center">
		<h1 class="text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
			{copy.home.title}
		</h1>
		<p class="mx-auto mt-5 max-w-2xl text-base leading-relaxed text-fg-2 sm:text-lg">
			{copy.home.subtitle}
		</p>
		<div class="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
			{#if checked && me}
				<Button class="h-11 rounded-sm px-6" href="/account">
					{copy.home.enterAccount}
					<ArrowRight size={16} aria-hidden="true" />
				</Button>
			{:else}
				<Button class="h-11 rounded-sm px-6" type="button" onclick={login}>
					{copy.home.login}
					<ArrowRight size={16} aria-hidden="true" />
				</Button>
			{/if}
			<Button variant="outline" class="h-11 rounded-sm px-6" href="/device">
				<KeyRound size={16} aria-hidden="true" />
				{copy.home.approveDevice}
			</Button>
		</div>
		{#if checked && me}
			<p class="mt-4 text-sm text-fg-3">{copy.home.signedInAs(me.user.display_name)}</p>
		{/if}
	</section>

	<section class="mt-20 grid gap-4 sm:mt-24 sm:grid-cols-3">
		{#each features as feature (feature.title)}
			{@const Icon = feature.icon}
			<div class="rounded-md border border-border bg-surface p-5">
				<Icon size={20} strokeWidth={1.7} class="text-fg-3" aria-hidden="true" />
				<h2 class="mt-4 text-base font-semibold">{feature.title}</h2>
				<p class="mt-2 text-sm leading-relaxed text-fg-2">{feature.body}</p>
			</div>
		{/each}
	</section>

	<section class="mt-20 sm:mt-24">
		<h2 class="text-2xl font-semibold tracking-tight">{copy.home.workflow}</h2>
		<div class="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
			{#each steps as step (step.n)}
				<div>
					<div class="font-mono text-sm text-fg-3">{step.n}</div>
					<h3 class="mt-2 text-base font-semibold">{step.title}</h3>
					<p class="mt-1.5 text-sm leading-relaxed text-fg-2">{step.body}</p>
				</div>
			{/each}
		</div>
	</section>
</SiteLayout>
