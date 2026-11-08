<script lang="ts">
	import { onMount } from 'svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import Modal from '#lib/components/admin/Modal.svelte';
	import {
		ApiError,
		adminUserPageSchema,
		adminUserSchema,
		apiGet,
		apiPatch,
		type AdminUser
	} from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';
	import { formatTime } from '#lib/admin/format.ts';

	let items = $state<AdminUser[]>([]);
	let cursor = $state<string | null>(null);
	let loading = $state(true);
	let loadingMore = $state(false);
	let error = $state('');
	let notice = $state('');
	let busyId = $state('');
	let banOpen = $state(false);
	let banTarget = $state<AdminUser | null>(null);

	onMount(() => {
		void load(true);
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
			const page = await apiGet(`/api/admin/users?${params}`, adminUserPageSchema);
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

	async function changeRole(user: AdminUser, role: string): Promise<void> {
		if (busyId) return;
		busyId = user.id;
		error = '';
		notice = '';
		try {
			const updated = await apiPatch(`/api/admin/users/${user.id}`, { role }, adminUserSchema);
			items = items.map((item) => (item.id === updated.id ? updated : item));
			notice = copy.admin.users.roleChanged;
		} catch (cause) {
			error = `${copy.admin.users.roleFailed}${describe(cause)}`;
			await load(true);
		} finally {
			busyId = '';
		}
	}

	async function setStatus(user: AdminUser, status: 'active' | 'banned'): Promise<void> {
		if (busyId) return;
		busyId = user.id;
		error = '';
		notice = '';
		try {
			const updated = await apiPatch('/api/admin/users/' + user.id, { status }, adminUserSchema);
			items = items.map((item) => (item.id === updated.id ? updated : item));
			notice = status === 'banned' ? copy.admin.users.banned : copy.admin.users.unbanned;
		} catch (cause) {
			error = copy.admin.users.statusFailed + describe(cause);
			await load(true);
		} finally {
			busyId = '';
			banOpen = false;
			banTarget = null;
		}
	}
</script>

<div>
	<h2 class="text-lg font-semibold">{copy.admin.users.title}</h2>
	<p class="mt-1 text-sm text-fg-2">{copy.admin.users.subtitle}</p>
</div>

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
					<th class="px-4 py-2 font-medium">{copy.admin.users.displayName}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.users.role}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.users.status}</th>
					<th class="px-4 py-2 font-medium">{copy.admin.users.createdAt}</th>
				</tr>
			</thead>
			<tbody>
				{#each items as user (user.id)}
					<tr class="border-b border-border last:border-0">
						<td class="px-4 py-3 align-top">
							<div class="font-medium">{user.display_name}</div>
							<div class="mt-1 break-all font-mono text-xs text-fg-3">{user.id}</div>
						</td>
						<td class="px-4 py-3 align-top">
							<select
								class="input h-9"
								value={user.role}
								disabled={busyId === user.id}
								onchange={(event) => changeRole(user, event.currentTarget.value)}
							>
								<option value="user">{copy.admin.role.user}</option>
								<option value="admin">{copy.admin.role.admin}</option>
							</select>
						</td>
						<td class="px-4 py-3 align-top">
							<div class="flex items-center gap-2">
								<span class="text-xs">
									{copy.admin.userStatus[user.status as keyof typeof copy.admin.userStatus] ?? user.status}
								</span>
								{#if user.status === 'banned'}
									<Button
										variant="outline"
										class="h-8 px-3 text-xs"
										type="button"
										disabled={busyId === user.id}
										onclick={() => setStatus(user, 'active')}
									>
										{copy.admin.users.unban}
									</Button>
								{:else}
									<Button
										variant="outline"
										class="h-8 px-3 text-xs"
										type="button"
										disabled={busyId === user.id}
										onclick={() => {
											banTarget = user;
											banOpen = true;
										}}
									>
										{copy.admin.users.ban}
									</Button>
								{/if}
							</div>
						</td>
						<td class="px-4 py-3 align-top text-xs text-fg-3">{formatTime(user.created_at)}</td>
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

<Modal bind:open={banOpen} title={copy.admin.users.ban} description={copy.admin.users.banConfirm}>
	<div class="flex justify-end gap-2">
		<Button variant="outline" type="button" onclick={() => (banOpen = false)}>{copy.admin.cancel}</Button>
		<Button type="button" onclick={() => banTarget && setStatus(banTarget, 'banned')}>
			{copy.admin.confirm}
		</Button>
	</div>
</Modal>
