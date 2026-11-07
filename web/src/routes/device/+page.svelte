<script lang="ts">
	import { onMount } from 'svelte';
	import { AlertCircle, ArrowRight, KeyRound } from 'lucide-svelte';
	import { z } from 'zod';
	import AuthLayout from '#lib/components/layouts/AuthLayout.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { fetchProviders, readQuery, type Provider } from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';

	// Matches `USER_CODE_ALPHABET` in the backend: I, O, 0 and 1 are excluded
	// because they are the pairs people misread. Accepting them here would only
	// spend a round trip to be told the code does not exist.
	const codeSchema = z
		.string()
		.regex(/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/, copy.device.codeFormat);

	let code = $state('');
	let error = $state('');
	let submitting = $state(false);
	let providers = $state<Provider[]>([]);
	let provider = $state('');
	let providersLoading = $state(true);
	let providerError = $state('');

	onMount(async () => {
		const raw = readQuery('user_code');
		if (raw) {
			code = normalize(raw);
		}
		await loadProviders();
	});

	async function loadProviders(): Promise<void> {
		providersLoading = true;
		providerError = '';
		try {
			providers = await fetchProviders();
			provider = providers.length === 1 ? (providers[0]?.name ?? '') : '';
		} catch {
			providerError = copy.device.providersUnavailable;
		} finally {
			providersLoading = false;
		}
	}

	function normalize(value: string): string {
		const compact = value.toUpperCase().replace(/[^A-Z0-9]/g, '');
		return compact.length === 8 ? `${compact.slice(0, 4)}-${compact.slice(4)}` : value.toUpperCase();
	}

	function submit(event: SubmitEvent): void {
		event.preventDefault();
		if (submitting || providersLoading) return;
		const parsed = codeSchema.safeParse(normalize(code));
		if (!parsed.success) {
			error = parsed.error.issues[0]?.message ?? copy.device.codeInvalid;
			return;
		}
		if (providers.length === 0) {
			error = copy.device.noProviders;
			return;
		}
		if (providers.length > 1 && !provider) {
			error = copy.device.providerRequired;
			return;
		}
		error = '';
		submitting = true;
		const query = new URLSearchParams({ user_code: parsed.data });
		if (provider) query.set('idp', provider);
		window.location.assign(`/device/start?${query.toString()}`);
	}
</script>

<AuthLayout
	title={copy.device.title}
	subtitle={copy.device.subtitle}
>
	<form onsubmit={submit}>
		<Label class="mb-1.5 block" for="user-code">{copy.device.codeLabel}</Label>
		<Input
			id="user-code"
			class="mono h-11 rounded-sm"
			name="user_code"
			autocomplete="one-time-code"
			autocapitalize="characters"
			spellcheck="false"
			inputmode="text"
			maxlength={9}
			placeholder="ABCD-EFGH"
			bind:value={code}
			oninput={() => {
				error = '';
				code = normalize(code);
			}}
		/>
		{#if providers.length > 1}
			<Label class="mt-4 mb-1.5 block" for="provider">{copy.device.providerLabel}</Label>
			<select id="provider" class="input" bind:value={provider}>
				<option value="">{copy.device.providerPlaceholder}</option>
				{#each providers as item (item.name)}
					<option value={item.name}>{item.display_name}</option>
				{/each}
			</select>
		{/if}
		<p class="field-hint">{copy.device.hint}</p>
		<div class="auth-actions">
			<Button
				class="h-11 w-full rounded-sm"
				type="submit"
				disabled={submitting || providersLoading}
			>
				<KeyRound size={16} aria-hidden="true" />
				{copy.device.submit}
				<ArrowRight size={16} aria-hidden="true" />
			</Button>
		</div>
	</form>

	{#if providerError}
		<Alert variant="destructive" class="mt-4 rounded-md">
			<AlertCircle />
			<AlertDescription>{providerError}</AlertDescription>
		</Alert>
		<div class="auth-actions">
			<Button variant="outline" class="h-11 w-full rounded-sm" type="button" onclick={loadProviders}>
				{copy.common.retry}
			</Button>
		</div>
	{/if}

	{#if error}
		<Alert variant="destructive" class="mt-4 rounded-md">
			<AlertCircle />
			<AlertDescription>{error}</AlertDescription>
		</Alert>
	{/if}
</AuthLayout>
