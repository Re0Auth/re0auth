<script lang="ts">
	import { onMount } from 'svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import {
		ApiError,
		adminAuditPageSchema,
		apiGet,
		type AdminAudit
	} from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';
	import { copyText, formatTime } from '#lib/admin/format.ts';

	let items = $state<AdminAudit[]>([]);
	let cursor = $state<string | null>(null);
	let loading = $state(true);
	let loadingMore = $state(false);
	let error = $state('');
	let copiedId = $state('');
	let copyFailedId = $state('');

	// 时间输入是本地 datetime-local，服务端只要 Unix 秒。
	let filter = $state({ actor: '', client: '', action: '', tier: '', from: '', to: '' });

	onMount(() => {
		void load(true);
	});

	function unix(value: string): string | null {
		if (!value) return null;
		const ms = new Date(value).getTime();
		return Number.isNaN(ms) ? null : String(Math.floor(ms / 1000));
	}

	function queryParams(): URLSearchParams {
		const params = new URLSearchParams({ limit: '50' });
		if (filter.actor.trim()) params.set('actor', filter.actor.trim());
		if (filter.client.trim()) params.set('client', filter.client.trim());
		if (filter.action.trim()) params.set('action', filter.action.trim());
		if (filter.tier) params.set('tier', filter.tier);
		const from = unix(filter.from);
		const to = unix(filter.to);
		if (from) params.set('from', from);
		if (to) params.set('to', to);
		return params;
	}

	async function load(reset: boolean): Promise<void> {
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
			const page = await apiGet(`/api/admin/audit?${params}`, adminAuditPageSchema);
			items = reset ? page.items : [...items, ...page.items];
			cursor = page.next_cursor;
		} catch (cause) {
			error = describe(cause);
		} finally {
			loading = false;
			loadingMore = false;
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

	async function copyId(id: string): Promise<void> {
		if (await copyText(id)) {
			copiedId = id;
			copyFailedId = '';
		} else {
			copyFailedId = id;
			copiedId = '';
		}
	}
</script>

<div>
	<h2 class="text-lg font-semibold">{copy.admin.audit.title}</h2>
	<p class="mt-1 text-sm text-fg-2">{copy.admin.audit.subtitle}</p>
</div>

<form
	class="mt-4 flex flex-wrap items-end gap-3"
	onsubmit={(event) => {
		event.preventDefault();
		void load(true);
	}}
>
	<div>
		<Label class="mb-1.5 block" for="audit-actor">{copy.admin.audit.actor}</Label>
		<Input id="audit-actor" class="h-9 w-64 rounded-sm font-mono text-xs" bind:value={filter.actor} />
	</div>
	<div>
		<Label class="mb-1.5 block" for="audit-client">{copy.admin.audit.client}</Label>
		<Input id="audit-client" class="h-9 w-64 rounded-sm font-mono text-xs" bind:value={filter.client} />
	</div>
	<div>
		<Label class="mb-1.5 block" for="audit-action">{copy.admin.audit.action}</Label>
		<Input
			id="audit-action"
			class="h-9 w-44 rounded-sm font-mono text-xs"
			placeholder={copy.admin.audit.actionHint}
			bind:value={filter.action}
		/>
	</div>
	<div>
		<Label class="mb-1.5 block" for="audit-tier">{copy.admin.audit.tier}</Label>
		<select id="audit-tier" class="input h-9" bind:value={filter.tier}>
			<option value="">—</option>
			<option value="fact">{copy.admin.tier.fact}</option>
			<option value="telemetry">{copy.admin.tier.telemetry}</option>
		</select>
	</div>
	<div>
		<Label class="mb-1.5 block" for="audit-from">{copy.admin.audit.from}</Label>
		<input id="audit-from" type="datetime-local" class="input h-9" bind:value={filter.from} />
	</div>
	<div>
		<Label class="mb-1.5 block" for="audit-to">{copy.admin.audit.to}</Label>
		<input id="audit-to" type="datetime-local" class="input h-9" bind:value={filter.to} />
	</div>
	<Button type="submit">{copy.admin.audit.apply}</Button>
	<Button
		variant="outline"
		type="button"
		onclick={() => {
			filter = { actor: '', client: '', action: '', tier: '', from: '', to: '' };
			void load(true);
		}}>{copy.admin.audit.reset}</Button
	>
</form>

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
					<th class="px-4 py-2 font-medium">{copy.admin.time}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.audit.action}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.audit.outcome}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.audit.severity}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.audit.detail}</th>
				</tr>
			</thead>
			<tbody>
				{#each items as record (record.id)}
					<tr class="border-b border-border last:border-0">
						<td class="px-4 py-3 align-top text-xs text-fg-3">{formatTime(record.occurred_at)}</td>
						<td class="px-4 py-3 align-top font-mono text-xs">{record.action}</td>
						<td class="px-4 py-3 align-top text-xs">
							{copy.admin.outcome[record.outcome as keyof typeof copy.admin.outcome] ?? record.outcome}
						</td>
						<td class="px-4 py-3 align-top text-xs">
							{copy.admin.severity[record.severity as keyof typeof copy.admin.severity] ?? record.severity}
						</td>
						<td class="px-4 py-3 align-top">
							<div class="max-w-xl break-words text-xs">{record.detail}</div>
							<div class="mt-1 break-all font-mono text-xs text-fg-3">{record.target}</div>
							{#if record.request_id}
								<button
									class="mt-1 break-all text-left font-mono text-xs text-fg-3 underline decoration-dotted"
									type="button"
									onclick={() => copyId(record.request_id ?? '')}
								>
									{record.request_id}
									{#if copiedId === record.request_id}· {copy.admin.copied}{:else if copyFailedId === record.request_id}· {copy.admin.copyFailed}{/if}
								</button>
							{/if}
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
