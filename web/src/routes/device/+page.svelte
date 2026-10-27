<script lang="ts">
	import { onMount } from 'svelte';
	import { AlertCircle, ArrowRight, KeyRound } from 'lucide-svelte';
	import { z } from 'zod';
	import AuthShell from '#lib/components/AuthShell.svelte';
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

<AuthShell
	title="批准设备"
	subtitle="输入设备上显示的代码。登录后确认授权，设备即可访问你的账号。"
>
	<form onsubmit={submit}>
		<label class="field-label" for="user-code">设备码</label>
		<input
			id="user-code"
			class="input mono"
			name="user_code"
			autocomplete="one-time-code"
			autocapitalize="characters"
			spellcheck="false"
			inputmode="text"
			maxlength="9"
			placeholder="ABCD-EFGH"
			bind:value={code}
			oninput={() => {
				error = '';
				code = normalize(code);
			}}
		/>
		{#if providers.length > 1}
			<label class="field-label" for="provider">登录方式</label>
			<select id="provider" class="input" bind:value={provider}>
				<option value="">请选择登录方式</option>
				{#each providers as item (item.name)}
					<option value={item.name}>{item.display_name}</option>
				{/each}
			</select>
		{/if}
		<p class="field-hint">代码通常显示在设备或机器人应用里。登录后还会再次确认权限。</p>
		<div class="auth-actions">
			<button class="btn-primary" type="submit" disabled={submitting || providersLoading}>
				<KeyRound size={16} aria-hidden="true" />
				继续
				<ArrowRight size={16} aria-hidden="true" />
			</button>
		</div>
	</form>

	{#if providerError}
		<div class="alert" role="alert">
			<AlertCircle size={16} aria-hidden="true" />
			<span>{providerError}</span>
			<button class="btn-secondary" type="button" onclick={loadProviders}>重试</button>
		</div>
	{/if}

	{#if error}
		<div class="alert" role="alert">
			<AlertCircle size={16} aria-hidden="true" />
			<span>{error}</span>
		</div>
	{/if}
</AuthShell>
