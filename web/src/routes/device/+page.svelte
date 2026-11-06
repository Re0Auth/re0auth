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

	// Matches `USER_CODE_ALPHABET` in the backend: I, O, 0 and 1 are excluded
	// because they are the pairs people misread. Accepting them here would only
	// spend a round trip to be told the code does not exist.
	const codeSchema = z
		.string()
		.regex(/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/, '请输入形如 ABCD-EFGH 的设备码。');

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
			providerError = '无法读取登录方式，请稍后重试。';
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
			error = parsed.error.issues[0]?.message ?? '设备码格式不正确。';
			return;
		}
		if (providers.length === 0) {
			error = '当前未配置登录方式，请联系站点管理员。';
			return;
		}
		if (providers.length > 1 && !provider) {
			error = '请选择登录方式。';
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
	title="批准设备"
	subtitle="输入设备上显示的代码。登录后确认授权，设备即可访问你的账号。"
>
	<form onsubmit={submit}>
		<Label class="mb-1.5 block" for="user-code">设备码</Label>
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
			<Label class="mt-4 mb-1.5 block" for="provider">登录方式</Label>
			<select id="provider" class="input" bind:value={provider}>
				<option value="">请选择登录方式</option>
				{#each providers as item (item.name)}
					<option value={item.name}>{item.display_name}</option>
				{/each}
			</select>
		{/if}
		<p class="field-hint">代码通常显示在设备或机器人应用中，登录后请根据你的需要，再次确认权限。</p>
		<div class="auth-actions">
			<Button
				class="h-11 w-full rounded-sm"
				type="submit"
				disabled={submitting || providersLoading}
			>
				<KeyRound size={16} aria-hidden="true" />
				继续
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
				重试
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
