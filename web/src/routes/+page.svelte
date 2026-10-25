<script lang="ts">
	import { ArrowRight, KeyRound, ShieldCheck } from 'lucide-svelte';
	import AuthShell from '#lib/components/AuthShell.svelte';
</script>

<AuthShell
	title="Re0Auth"
	subtitle="音游数据的身份与委托授权层。选择一个入口继续。"
>
	<div class="auth-actions">
		<a class="btn-primary" href="/login">
			登录
			<ArrowRight size={16} aria-hidden="true" />
		</a>
		<a class="btn-secondary" href="/device">
			<KeyRound size={16} aria-hidden="true" />
			批准设备
		</a>
		<a class="btn-secondary" href="/account">
			<ShieldCheck size={16} aria-hidden="true" />
			账号与授权
		</a>
	</div>
	<p class="meta">登录由外部身份提供商处理，Re0Auth 不保存密码。</p>
	<p class="meta"><a href="/about">这个实例由谁运营、能碰到什么</a></p>
</AuthShell>
