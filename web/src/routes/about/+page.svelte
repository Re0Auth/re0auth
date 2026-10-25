<script lang="ts">
	import { ArrowRight, Info } from 'lucide-svelte';
	import AuthShell from '#lib/components/AuthShell.svelte';
</script>

<AuthShell
	title="关于这个实例"
	subtitle="这里说明谁在运营、它能碰到什么，以及哪些话我们不打算说。"
>
	<h2 class="section-title">这是什么</h2>
	<p>
		Re0Auth 是音游数据的身份与委托授权层。你在下游（查分机器人、网页看板）用一次登录完成授权，
		之后换一个下游不必重新交一遍游戏凭据，也可以单独撤销某一个下游而不影响其他。
	</p>

	<h2 class="section-title">谁在运营</h2>
	<p>
		这个公共实例由空间站「镜湖」运营，域名 <span class="mono">re0auth.r0semi.net</span>。
		自托管部署的实例由部署方运营，本段应由运营方替换为自己的说明。
	</p>
	<p class="meta">你的账号由外部身份提供商（如 Google、Microsoft、Discord）管理，Re0Auth 不保存密码。</p>

	<h2 class="section-title">游戏账号凭据</h2>
	<p>
		提供游戏数据的上游（例如 Phi Backend API、PhiHub）需要凭据才能取数。这些凭据由
		<strong>Connector</strong> 持有：可以保存在独立的加密存储里，也可以只在内存中转、用完即清；
		它们不进核心数据库，也不进日志。
	</p>
	<div class="notice" role="note">
		<Info size={16} aria-hidden="true" />
		<span>
			这不是「我们从不接触你的游戏凭据」的承诺。内核不存根凭证是为了让内核小、稳定、可替换——
			那是工程卫生，不是隐私保证。
		</span>
	</div>

	<h2 class="section-title">你能控制什么</h2>
	<ul class="scope-list">
		<li class="scope-item">按下游逐个授权，权限范围在同意页逐项列出。</li>
		<li class="scope-item">在「账号与授权」里逐个撤销；撤销后该下游再也取不到数据。</li>
		<li class="scope-item">授权决定与数据访问都有审计记录（只记元数据，不记响应体）。</li>
	</ul>

	<h2 class="section-title">什么情况下才算强保证</h2>
	<p>
		只有<strong>自带 Connector</strong>（BYOC，bring your own connector）才是强保证：那时你或你信任的
		一方自己运营 Connector，凭据完全不经过我们。本实例<strong>自带 Connector</strong>，凭据由运营者负责。
	</p>

	<h2 class="section-title">我们不打算说的话</h2>
	<ul class="scope-list">
		<li class="scope-item">不说「你的游戏账号绝对安全」。没有任何授权层能做出这种承诺。</li>
		<li class="scope-item">不把「内核不存根凭证」包装成隐私保证。</li>
		<li class="scope-item">不承诺上游永远可用。上游不可用时登录仍然能用，取数会失败并如实回报。</li>
	</ul>

	<div class="auth-actions">
		<a class="btn-primary" href="/account">
			账号与授权
			<ArrowRight size={16} aria-hidden="true" />
		</a>
		<a class="btn-secondary" href="/">返回</a>
	</div>
</AuthShell>
