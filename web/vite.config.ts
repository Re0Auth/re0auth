import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

const backend = 'http://127.0.0.1:8080';

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			adapter: adapter({ fallback: 'index.html' }),
			csp: {
				mode: 'hash',
				directives: {
					'default-src': ['self'],
					'script-src': ['self'],
					'style-src': ['self', 'unsafe-inline'],
					'img-src': ['self', 'data:'],
					'connect-src': ['self'],
					'font-src': ['self'],
					'form-action': ['self'],
					'base-uri': ['none'],
					'object-src': ['none']
				}
			}
		})
	],
	server: {
		proxy: {
			'/auth': backend,
			'/api': backend,
			'/oauth': backend,
			'/userinfo': backend,
			'/jwks.json': backend,
			'/.well-known': backend,
			'/device/start': backend,
			'/device/approve': backend,
			'/device/deny': backend
		}
	}
});
