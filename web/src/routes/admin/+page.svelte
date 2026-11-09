<script lang="ts">
	import { onMount } from 'svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { ApiError, apiGet, adminStatsSchema, type AdminStats } from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';

	let stats = $state<AdminStats | null>(null);
	let error = $state('');

	onMount(async () => {
		try {
			stats = await apiGet('/api/admin/stats', adminStatsSchema);
		} catch (cause) {
			error = cause instanceof ApiError ? `${cause.code}: ${cause.message}` : copy.admin.loadFailed;
		}
	});

	const cards = $derived([
		{ key: 'users', label: copy.admin.stats.users, value: stats?.users ?? 0 },
		{ key: 'clients', label: copy.admin.stats.clients, value: stats?.clients ?? 0 },
		{ key: 'bindings', label: copy.admin.stats.activeBindings, value: stats?.active_bindings ?? 0 },
		{ key: 'audit', label: copy.admin.stats.auditRecords, value: stats?.audit_records ?? 0 }
	]);
</script>

<h2 class="text-lg font-semibold">{copy.admin.stats.title}</h2>
<p class="meta mt-1">{copy.admin.stats.subtitle}</p>

{#if error}
	<Alert variant="destructive" class="mt-4 rounded-md">
		<AlertDescription>{error}</AlertDescription>
	</Alert>
{:else if !stats}
	<p class="meta mt-4">{copy.admin.loading}</p>
{:else}
	<div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
		{#each cards as card (card.key)}
			<div class="rounded-md border border-border p-4">
				<p class="meta">{card.label}</p>
				<p class="mt-1 text-2xl font-semibold tabular-nums">{card.value}</p>
			</div>
		{/each}
	</div>
{/if}
