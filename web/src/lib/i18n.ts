import zh from '../../../locales/zh-CN.json';
import en from '../../../locales/en.json';

export type Locale = 'zh-CN' | 'en';

const catalogs: Record<Locale, Record<string, string>> = { 'zh-CN': zh, en };

export function currentLocale(): Locale {
	if (typeof document === 'undefined') return 'zh-CN';
	const cookie = document.cookie
		.split(';')
		.map((part) => part.trim())
		.find((part) => part.startsWith('re0auth_lang='));
	const value = cookie?.split('=')[1];
	return value === 'en' ? 'en' : 'zh-CN';
}

export function lookup(key: string): string | undefined {
	return catalogs[currentLocale()][key];
}

export function t(key: string): string {
	return lookup(key) ?? catalogs['zh-CN'][key] ?? key;
}

export function setLocale(locale: Locale): void {
	if (typeof document === 'undefined') return;
	document.cookie = `re0auth_lang=${locale}; Path=/; Max-Age=31536000; SameSite=Lax`;
	location.reload();
}

/** Recursively overlay catalog values by dotted path; unknown paths keep the source string. */
export function localize<T>(value: T, path = ''): T {
	if (typeof value === 'string') return (lookup(path) ?? value) as T;
	if (Array.isArray(value)) {
		return value.map((item, index) => localize(item, path ? `${path}.${index}` : `${index}`)) as T;
	}
	if (typeof value === 'object' && value !== null) {
		return new Proxy(value, {
			get(target, property) {
				const key = String(property);
				const child = Reflect.get(target, property);
				return localize(child, path ? `${path}.${key}` : key);
			}
		});
	}
	return value;
}
