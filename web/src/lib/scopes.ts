const descriptions: Record<string, string> = {
	openid: '确认你的身份',
	profile: '读取你的基础资料',
	'phigros.xtower.read': '读取你的 Phigros 游戏数据（Phigros Query 数据源）',
	'phigros.phihub.read': '读取你的 Phigros 游戏数据（PhiHub 数据源）'
};

export function scopeDescription(scope: string): string {
	return descriptions[scope] ?? '访问该权限范围';
}

export function scopeSummary(scopes: string[]): string {
	return scopes.map(scopeDescription).join('、');
}
