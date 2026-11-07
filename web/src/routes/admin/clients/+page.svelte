<script lang="ts">
	import { onMount } from 'svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import Modal from '#lib/components/admin/Modal.svelte';
	import {
		ApiError,
		adminClientPageSchema,
		adminClientSchema,
		apiGet,
		apiPatch,
		apiPost,
		createdClientSchema,
		rotatedSecretSchema,
		type AdminClient
	} from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';
	import { copyText, formatTime } from '#lib/admin/format.ts';

	let items = $state<AdminClient[]>([]);
	let cursor = $state<string | null>(null);
	let loading = $state(true);
	let loadingMore = $state(false);
	let error = $state('');

	let formOpen = $state(false);
	let editingId = $state<string | null>(null);
	let editingUpdatedAt = $state<number | null>(null);
	let saving = $state(false);
	let formError = $state('');
	let form = $state({
		name: '',
		redirectUris: '',
		scopes: 'openid',
		confidential: false,
		rawAccess: false,
		status: 'pending'
	});

	let secretOpen = $state(false);
	let secret = $state<{ id: string; secret: string } | null>(null);
	let copied = $state(false);

	let busyId = $state('');
	let rotateTarget = $state<AdminClient | null>(null);
	let rotateOpen = $state(false);

	const statuses = ['pending', 'approved', 'suspended', 'revoked'] as const;

	onMount(() => {
		void load(true);
	});

	$effect(() => {
		if (!secretOpen) secret = null;
	});

	async function load(reset: boolean): Promise<void> {
		error = '';
		if (reset) {
			loading = true;
			cursor = null;
		} else {
			loadingMore = true;
		}
		try {
			const params = new URLSearchParams({ limit: '50' });
			if (!reset && cursor) params.set('cursor', cursor);
			const page = await apiGet(`/api/admin/clients?${params}`, adminClientPageSchema);
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

	function lines(text: string): string[] {
		return text
			.split('\n')
			.map((line) => line.trim())
			.filter((line) => line.length > 0);
	}

	function openCreate(): void {
		editingId = null;
		editingUpdatedAt = null;
		formError = '';
		form = { name: '', redirectUris: '', scopes: 'openid', confidential: false, rawAccess: false, status: 'pending' };
		formOpen = true;
	}

	function openEdit(client: AdminClient): void {
		editingId = client.id;
		editingUpdatedAt = client.updated_at;
		formError = '';
		form = {
			name: client.name,
			redirectUris: client.redirect_uris.join('\n'),
			scopes: client.allowed_scopes.join('\n'),
			confidential: client.has_secret,
			rawAccess: client.raw_access,
			status: client.status
		};
		formOpen = true;
	}

	async function submit(): Promise<void> {
		if (saving) return;
		saving = true;
		formError = '';
		try {
			if (editingId) {
				const updated = await apiPatch(
					`/api/admin/clients/${editingId}`,
					{
						name: form.name.trim(),
						redirect_uris: lines(form.redirectUris),
						allowed_scopes: lines(form.scopes),
						raw_access: form.rawAccess,
						status: form.status,
						expected_updated_at: editingUpdatedAt
					},
					adminClientSchema
				);
				items = items.map((item) => (item.id === updated.id ? updated : item));
				formOpen = false;
			} else {
				const created = await apiPost(
					'/api/admin/clients',
					{
						name: form.name.trim(),
						redirect_uris: lines(form.redirectUris),
						allowed_scopes: lines(form.scopes),
						confidential: form.confidential,
						raw_access: form.rawAccess,
						status: form.status
					},
					createdClientSchema
				);
				formOpen = false;
				await load(true);
				if (created.secret) showSecret({ id: created.id, secret: created.secret });
			}
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 409) {
				formError = copy.admin.clients.conflict;
				await load(true);
			} else {
				const prefix = editingId
					? copy.admin.clients.updateFailed
					: copy.admin.clients.createFailed;
				formError = `${prefix}${describe(cause)}`;
			}
		} finally {
			saving = false;
		}
	}

	async function rotate(client: AdminClient): Promise<void> {
		if (busyId) return;
		busyId = client.id;
		rotateTarget = null;
		rotateOpen = false;
		error = '';
		try {
			const rotated = await apiPost(
				`/api/admin/clients/${client.id}/rotate-secret`,
				{},
				rotatedSecretSchema
			);
			await load(true);
			showSecret(rotated);
		} catch (cause) {
			error = describe(cause);
		} finally {
			busyId = '';
		}
	}

	function showSecret(value: { id: string; secret: string }): void {
		secret = value;
		copied = false;
		secretOpen = true;
	}

	async function copySecret(): Promise<void> {
		if (!secret) return;
		copied = await copyText(secret.secret);
	}
</script>

<div class="flex flex-wrap items-start justify-between gap-3">
	<div>
		<h2 class="text-lg font-semibold">{copy.admin.clients.title}</h2>
		<p class="mt-1 text-sm text-fg-2">{copy.admin.clients.subtitle}</p>
	</div>
	<Button type="button" onclick={openCreate}>{copy.admin.clients.newClient}</Button>
</div>

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
					<th class="px-4 py-2 font-medium">{copy.admin.clients.name}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.clients.status}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.clients.allowedScopes}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.clients.updatedAt}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.clients.action}</th>
				</tr>
			</thead>
			<tbody>
				{#each items as client (client.id)}
					<tr class="border-b border-border last:border-0">
						<td class="px-4 py-3 align-top">
							<div class="font-medium">{client.name}</div>
							<div class="mt-1 break-all font-mono text-xs text-fg-3">{client.id}</div>
							<div class="mt-1 break-all text-xs text-fg-3">{client.redirect_uris.join(' , ')}</div>
						</td>
						<td class="px-4 py-3 align-top">
							<span class="rounded-sm border border-border px-2 py-0.5 text-xs">
								{copy.admin.status[client.status as keyof typeof copy.admin.status] ?? client.status}
							</span>
							<div class="mt-1 text-xs text-fg-3">
								{client.has_secret ? copy.admin.clients.hasSecret : copy.admin.clients.noSecret}
								{#if client.raw_access}· {copy.admin.clients.rawAccess}{/if}
							</div>
						</td>
						<td class="px-4 py-3 align-top font-mono text-xs text-fg-2">
							{client.allowed_scopes.join(' ')}
						</td>
						<td class="px-4 py-3 align-top text-xs text-fg-3">{formatTime(client.updated_at)}</td>
						<td class="px-4 py-3 align-top">
							<div class="flex flex-wrap gap-2">
								<Button variant="outline" class="h-8 px-3 text-xs" type="button" onclick={() => openEdit(client)}>
									{copy.admin.edit}
								</Button>
								<Button
									variant="outline"
									class="h-8 px-3 text-xs"
									type="button"
									disabled={busyId === client.id}
									onclick={() => {
										rotateTarget = client;
										rotateOpen = true;
									}}
								>
									{copy.admin.clients.rotate}
								</Button>
							</div>
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

<Modal
	bind:open={formOpen}
	title={editingId ? copy.admin.edit : copy.admin.clients.newClient}
	description={copy.admin.clients.subtitle}
>
	<form
		class="space-y-4"
		onsubmit={(event) => {
			event.preventDefault();
			void submit();
		}}
	>
		<div>
			<Label class="mb-1.5 block" for="client-name">{copy.admin.clients.name}</Label>
			<Input id="client-name" class="h-10 rounded-sm" bind:value={form.name} />
		</div>
		<div>
			<Label class="mb-1.5 block" for="client-redirects">{copy.admin.clients.redirectUris}</Label>
			<textarea
				id="client-redirects"
				class="h-24 w-full rounded-sm border border-border bg-bg p-2 font-mono text-xs"
				bind:value={form.redirectUris}
			></textarea>
			<p class="mt-1 text-xs text-fg-3">{copy.admin.clients.redirectUrisHint}</p>
		</div>
		<div>
			<Label class="mb-1.5 block" for="client-scopes">{copy.admin.clients.allowedScopes}</Label>
			<textarea
				id="client-scopes"
				class="h-20 w-full rounded-sm border border-border bg-bg p-2 font-mono text-xs"
				bind:value={form.scopes}
			></textarea>
			<p class="mt-1 text-xs text-fg-3">{copy.admin.clients.allowedScopesHint}</p>
		</div>
		<div class="flex flex-wrap items-center gap-4 text-sm">
			<label class="flex items-center gap-2">
				<input type="checkbox" bind:checked={form.rawAccess} />
				{copy.admin.clients.rawAccess}
			</label>
			<label class="flex items-center gap-2">
				<input type="checkbox" bind:checked={form.confidential} disabled={editingId !== null} />
				{copy.admin.clients.confidential}
			</label>
			<label class="flex items-center gap-2">
				{copy.admin.clients.status}
				<select class="input h-9" bind:value={form.status}>
					{#each statuses as status (status)}
						<option value={status}>{copy.admin.status[status]}</option>
					{/each}
				</select>
			</label>
		</div>
		{#if formError}
			<Alert variant="destructive" class="rounded-md"><AlertDescription>{formError}</AlertDescription></Alert>
		{/if}
		<div class="flex justify-end gap-2">
			<Button variant="outline" type="button" onclick={() => (formOpen = false)}>{copy.admin.cancel}</Button>
			<Button type="submit" disabled={saving}>{copy.admin.save}</Button>
		</div>
	</form>
</Modal>

<Modal bind:open={secretOpen} title={copy.admin.clients.secretTitle} description={copy.admin.clients.secretWarning}>
	{#if secret}
		<code class="block break-all rounded-sm border border-border bg-surface p-3 text-sm">{secret.secret}</code>
		<div class="mt-3 flex justify-end gap-2">
			<Button variant="outline" type="button" onclick={copySecret}>
				{copied ? copy.admin.copied : copy.admin.copy}
			</Button>
			<Button type="button" onclick={() => (secretOpen = false)}>{copy.admin.close}</Button>
		</div>
	{/if}
</Modal>

<Modal
	bind:open={rotateOpen}
	title={copy.admin.clients.rotate}
	description={copy.admin.clients.rotateConfirm}
>
	<div class="flex justify-end gap-2">
		<Button variant="outline" type="button" onclick={() => (rotateOpen = false)}>{copy.admin.cancel}</Button>
		<Button type="button" onclick={() => rotateTarget && rotate(rotateTarget)}>{copy.admin.confirm}</Button>
	</div>
</Modal>
