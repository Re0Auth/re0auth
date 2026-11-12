<script lang="ts">
	import { onMount } from 'svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import Modal from '#lib/components/admin/Modal.svelte';
	import {
		ApiError,
		adminBindingPageSchema,
		apiDelete,
		apiGet,
		type AdminBinding
	} from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';
	import { formatTime } from '#lib/admin/format.ts';

	let items = $state<AdminBinding[]>([]);
	let cursor = $state<string | null>(null);
	let loading = $state(true);
	let loadingMore = $state(false);
	let querySequence = 0;
	let error = $state('');
	let notice = $state('');
	let busyId = $state('');
	let confirmOpen = $state(false);
	let target = $state<AdminBinding | null>(null);

	let filter = $state({ user: '', connector: '', status: '' });

	const statuses = ['pending', 'active', 'needs_reauth', 'revoked'] as const;

	onMount(() => {
		void load(true);
	});

	function queryParams(): URLSearchParams {
		const params = new URLSearchParams({ limit: '50' });
		if (filter.user.trim()) params.set('user', filter.user.trim());
		if (filter.connector.trim()) params.set('connector', filter.connector.trim());
		if (filter.status) params.set('status', filter.status);
		return params;
	}

	async function load(reset: boolean): Promise<void> {
		const request = ++querySequence;
		error = '';
		if (reset) {
			loading = true;
			cursor = null;
		} else {
			loadingMore = true;
		}
		try {
			const params = queryParams();
			if (!reset && cursor) params.set('cursor', cursor);
			const page = await apiGet(`/api/admin/bindings?${params}`, adminBindingPageSchema);
			if (request !== querySequence) return;
			items = reset ? page.items : [...items, ...page.items];
			cursor = page.next_cursor;
		} catch (cause) {
			if (request !== querySequence) return;
			error = describe(cause);
		} finally {
			if (request === querySequence) {
				loading = false;
				loadingMore = false;
			}
		}
	}

	function describe(cause: unknown): string {
		if (cause instanceof ApiError) {
			if (cause.status === 404) return copy.admin.notConfigured;
			if (cause.status === 403) return copy.admin.forbiddenBody;
			return `${cause.code}: ${cause.message}`;
		}
		return copy.admin.loadFailed;
	}

	function askRevoke(binding: AdminBinding): void {
		target = binding;
		confirmOpen = true;
	}

	async function revoke(): Promise<void> {
		if (!target || busyId) return;
		const binding = target;
		busyId = binding.id;
		confirmOpen = false;
		error = '';
		notice = '';
		try {
			await apiDelete(`/api/admin/bindings/${binding.id}`);
			items = items.map((item) =>
				item.id === binding.id ? { ...item, status: 'revoked' } : item
			);
			notice = copy.admin.bindings.revoked;
		} catch (cause) {
			error = `${copy.admin.bindings.revokeFailed}${describe(cause)}`;
		} finally {
			busyId = '';
			target = null;
		}
	}
</script>

<div>
	<h2 class="text-lg font-semibold">{copy.admin.bindings.title}</h2>
	<p class="mt-1 text-sm text-fg-2">{copy.admin.bindings.subtitle}</p>
</div>

<form
	class="mt-4 flex flex-wrap items-end gap-3"
	onsubmit={(event) => {
		event.preventDefault();
		void load(true);
	}}
>
	<div>
		<Label class="mb-1.5 block" for="binding-user">{copy.admin.bindings.user}</Label>
		<Input id="binding-user" class="h-9 w-64 rounded-sm font-mono text-xs" bind:value={filter.user} />
	</div>
	<div>
		<Label class="mb-1.5 block" for="binding-connector">{copy.admin.bindings.connector}</Label>
		<Input id="binding-connector" class="h-9 w-40 rounded-sm" bind:value={filter.connector} />
	</div>
	<div>
		<Label class="mb-1.5 block" for="binding-status">{copy.admin.bindings.status}</Label>
		<select id="binding-status" class="input h-9" bind:value={filter.status}>
			<option value="">—</option>
			{#each statuses as status (status)}
				<option value={status}>{copy.admin.status[status]}</option>
			{/each}
		</select>
	</div>
	<Button type="submit">{copy.admin.audit.apply}</Button>
	<Button
		variant="outline"
		type="button"
		onclick={() => {
			filter = { user: '', connector: '', status: '' };
			void load(true);
		}}>{copy.admin.audit.reset}</Button
	>
</form>

{#if notice}
	<Alert class="mt-4 rounded-md"><AlertDescription>{notice}</AlertDescription></Alert>
{/if}
{#if error}
	<Alert variant="destructive" class="mt-4 rounded-md"><AlertDescription>{error}</AlertDescription></Alert>
{/if}

{#if loading}
	<p class="meta mt-6">{copy.admin.loading}</p>
{:else if items.length === 0}
	<p class="meta mt-6">{copy.admin.empty}</p>
{:else}
	<div class="mt-6 overflow-x-auto rounded-md border border-border">
		<table class="w-full text-left text-sm">
			<thead class="border-b border-border bg-surface text-fg-2">
				<tr>
					<th class="px-4 py-2 font-medium">{copy.admin.bindings.user}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.bindings.connector}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.bindings.status}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.bindings.lastRefreshed}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.clients.action}</th>
				</tr>
			</thead>
			<tbody>
				{#each items as binding (binding.id)}
					<tr class="border-b border-border last:border-0">
						<td class="px-4 py-3 align-top">
							<div class="break-all font-mono text-xs">{binding.user_id}</div>
							<div class="mt-1 break-all font-mono text-xs text-fg-3">{binding.id}</div>
						</td>
						<td class="px-4 py-3 align-top">
							<div>{binding.connector}</div>
							<div class="mt-1 break-all font-mono text-xs text-fg-3">
								{binding.upstream_user_id}
							</div>
						</td>
						<td class="px-4 py-3 align-top">
							{copy.admin.status[binding.status as keyof typeof copy.admin.status] ?? binding.status}
							{#if binding.last_error_code}
								<div class="mt-1 text-xs text-fg-3">{binding.last_error_code}</div>
							{/if}
						</td>
						<td class="px-4 py-3 align-top text-xs text-fg-3">
							{formatTime(binding.last_refreshed_at)}
						</td>
						<td class="px-4 py-3 align-top">
							<Button
								variant="outline"
								class="h-8 px-3 text-xs"
								type="button"
								disabled={busyId === binding.id || binding.status === 'revoked'}
								onclick={() => askRevoke(binding)}
							>
								{copy.admin.bindings.revoke}
							</Button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	{#if cursor}
		<div class="auth-actions mt-4">
			<Button variant="outline" type="button" disabled={loadingMore} onclick={() => load(false)}>
				{copy.admin.loadMore}
			</Button>
		</div>
	{/if}
{/if}

<Modal bind:open={confirmOpen} title={copy.admin.bindings.revoke} description={copy.admin.bindings.revokeConfirm}>
	<div class="flex justify-end gap-2">
		<Button variant="outline" type="button" onclick={() => (confirmOpen = false)}>{copy.admin.cancel}</Button>
		<Button type="button" onclick={revoke}>{copy.admin.confirm}</Button>
	</div>
</Modal>
