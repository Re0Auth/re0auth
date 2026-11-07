// 管理后台的展示辅助：时间与复制。格式逻辑只此一份。

export function formatTime(unix: number | null | undefined): string {
	if (unix === null || unix === undefined) return '—';
	return new Intl.DateTimeFormat('zh-CN', {
		dateStyle: 'medium',
		timeStyle: 'short'
	}).format(new Date(unix * 1000));
}

/// 复制失败时返回 false，由调用方给出「请手动选择」的提示。
export async function copyText(value: string): Promise<boolean> {
	try {
		await navigator.clipboard.writeText(value);
		return true;
	} catch {
		return false;
	}
}
