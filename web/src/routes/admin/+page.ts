import { redirect } from '@sveltejs/kit';

// 管理后台没有总览页：直接落到第一个分区。
export function load(): never {
	redirect(307, '/admin/clients');
}
