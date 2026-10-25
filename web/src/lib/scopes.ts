const descriptions: Record<string, string> = {
	openid: '确认你的身份',
	profile: '读取你的基础资料',
	'phigros.stats.read': '读取 Phigros 统计数据',
	'phihub.save.read': '读取 PhiHub 云存档（资料、成绩、统计）'
};

export function scopeDescription(scope: string): string {
	return descriptions[scope] ?? '访问该权限范围';
}

export function scopeSummary(scopes: string[]): string {
	return scopes.map(scopeDescription).join('、');
}
