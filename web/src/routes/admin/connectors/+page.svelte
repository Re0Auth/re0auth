<script lang="ts">
	import { onMount } from 'svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import {
		ApiError,
		adminConnectorPageSchema,
		apiGet,
		type AdminConnector
	} from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';

	let items = $state<AdminConnector[]>([]);
	let loading = $state(true);
	let error = $state('');

	onMount(async () => {
		try {
			const page = await apiGet('/api/admin/connectors', adminConnectorPageSchema);
			items = page.items;
		} catch (cause) {
			error =
				cause instanceof ApiError
					? cause.status === 404
						? copy.admin.notConfigured
						: cause.status === 403
							? copy.admin.forbiddenBody
							: `${cause.code}: ${cause.message}`
					: copy.admin.loadFailed;
		} finally {
			loading = false;
		}
	});
</script>

<div>
	<h2 class="text-lg font-semibold">{copy.admin.connectors.title}</h2>
	<p class="mt-1 text-sm text-fg-2">{copy.admin.connectors.subtitle}</p>
</div>

{#if error}
	<Alert variant="destructive" class="mt-4 rounded-md"><AlertDescription>{error}</AlertDescription></Alert>
{:else if loading}
	<p class="meta mt-6">{copy.admin.loading}</p>
{:else if items.length === 0}
	<p class="meta mt-6">{copy.admin.empty}</p>
{:else}
	<div class="mt-6 space-y-6">
		{#each items as connector (connector.id)}
			<section class="rounded-md border border-border p-4">
				<div class="flex flex-wrap items-baseline justify-between gap-2">
					<h3 class="text-base font-semibold">{connector.display_name}</h3>
					<span class="break-all font-mono text-xs text-fg-3">{connector.id} · {connector.base_url}</span>
				</div>
				<p class="mt-1 text-xs text-fg-3">
					{connector.allow_private_net ? copy.admin.connectors.privateNet : ''}
				</p>
				<div class="mt-3 overflow-x-auto">
					<table class="w-full text-left text-sm">
						<thead class="border-b border-border text-fg-2">
							<tr>
								<th class="px-3 py-2 font-medium">{copy.admin.connectors.resourceName}</th>
								<th class="px-3 py-2 font-medium">{copy.admin.connectors.resourceMethod}</th>
								<th class="px-3 py-2 font-medium">{copy.admin.connectors.resourcePath}</th>
								<th class="px-3 py-2 font-medium">{copy.admin.connectors.resourceScope}</th>
							</tr>
						</thead>
						<tbody>
							{#each connector.resources as resource (resource.name)}
								<tr class="border-b border-border last:border-0">
									<td class="px-3 py-2">{resource.name}</td>
									<td class="px-3 py-2 font-mono text-xs">{resource.method}</td>
									<td class="px-3 py-2 break-all font-mono text-xs">{resource.path}</td>
									<td class="px-3 py-2 font-mono text-xs">{resource.scope}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/each}
	</div>
{/if}
