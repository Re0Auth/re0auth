//! 用户可见文案的唯一来源。
//!
//! 键名英文、值简体中文；改一句措辞只动这里。带参数的句子写成函数，
//! 含内联标记的句子按标记切段，由调用方把 <code>/<strong> 放回原位。
//!
//! 刻意不收：协议错误的 `error_description`、problem `detail`、审计与日志
//! （它们的稳定标识是 `code`），以及 `scopes.ts` 的权限描述表
//! （那是按协议 scope 字符串索引的数据），和 `content/about.md` 长文。

export const copy = {
	site: {
		name: 'Re0Auth',
		footer: 'Re0Auth · 音游数据的授权中间层',
		nav: {
			about: '关于',
			device: '批准设备',
			account: '账号与授权',
			login: '登录',
			admin: '管理',
			menu: '菜单'
		},
		theme: {
			light: '当前亮色，点击切换到暗色',
			dark: '当前暗色，点击切换到跟随系统',
			system: '当前跟随系统，点击切换到亮色'
		}
	},

	common: {
		retry: '重试',
		loading: '正在加载…',
		back: '返回'
	},

	home: {
		title: '一次登录，随时查分',
		subtitle: '音游数据的身份与授权层，为玩家和下游提供简单、方便、统一的授权服务',
		enterAccount: '进入账号与授权',
		login: '登录',
		approveDevice: '批准设备',
		signedInAs: (name: string) => `已登录：${name}`,
		features: {
			ssoTitle: '单点登录',
			ssoBody: '一次登录，即可适用于所有接入 Re0Auth 的下游应用，无需重复授权。',
			isolatedTitle: '凭据隔离',
			isolatedBody:
				'借助 OAuth2.0 等协议，Re0Auth 统一管理上游的访问凭证，不直接接触用户账号和密码。',
			mentalTitle: '统一心智',
			mentalBody: '玩家减少多次重复登录，下游减少多次重复适配。'
		},
		workflow: '工作流程',
		steps: {
			loginTitle: '登录',
			loginBody: '通过外部身份提供商（GitHub 等）完成登录。',
			bindTitle: '绑定游戏账号',
			bindBody: '连接上游游戏数据源，由其代为获取数据。',
			consentTitle: '确认授权',
			consentBody: '下游应用请求数据时，逐项确认权限范围。',
			revokeTitle: '撤销授权',
			revokeBody: '在账号页撤销单个应用，或一次性解除全部绑定。'
		}
	},

	login: {
		title: '登录 Re0Auth',
		subtitle: '通过外部身份提供商完成登录',
		loading: '正在读取登录方式…',
		providersUnavailable: '无法读取登录方式，请稍后重试。',
		noProviders: '当前未配置登录方式，请联系站点管理员。',
		continueWith: '继续登录',
		leaving: '登录过程会离开 Re0Auth，由外部 IdP 完成身份校验。',
		firstTime:
			'第一次用某个登录方式登录时会创建一个新账号。登录后可以在「账号与授权」页把其他登录方式加进来，同一个账号就能用多种方式登录。'
	},

	device: {
		title: '批准设备',
		subtitle: '输入设备上显示的代码。登录后确认授权，设备即可访问你的账号。',
		codeLabel: '设备码',
		codeFormat: '请输入形如 ABCD-EFGH 的设备码。',
		codeInvalid: '设备码格式不正确。',
		providersUnavailable: '无法读取登录方式，请稍后重试。',
		noProviders: '当前未配置登录方式，请联系站点管理员。',
		providerLabel: '登录方式',
		providerPlaceholder: '请选择登录方式',
		providerRequired: '请选择登录方式。',
		hint: '代码通常显示在设备或机器人应用中，登录后请根据你的需要，再次确认权限。',
		submit: '继续'
	},

	consent: {
		title: '确认授权',
		subtitle: (client: string) => `${client} 请求访问你的 Re0Auth 账号。`,
		loadingRequest: '正在读取授权请求…',
		loading: '正在加载…',
		missingRequest: '缺少授权请求参数，请返回发起授权的应用重新开始。',
		sessionExpired: '登录状态已失效，请返回发起授权的应用重新开始。',
		checkFailed: '安全校验失败，请刷新页面后重试。',
		requestNotFound: '授权请求不存在或不属于当前登录会话，请返回应用重新发起授权。',
		fallback: '请求失败，请稍后重试。',
		scopeList: '请求的权限范围',
		missingLead: '授权本身可以完成，但这些权限需要先连接对应的游戏账号才能读取数据：',
		connect: (upstream: string) => `连接 ${upstream}`,
		missingNote: '连接后回到本页继续授权。数据读取时才会校验绑定，未连接不会影响本次授权的完成。',
		redirectLead: '授权后将返回',
		redirectDue: '。请求将在',
		redirectExpire: '过期。',
		approve: '批准',
		deny: '拒绝'
	},

	account: {
		title: '账号与授权',
		subtitle: (name: string) => `${name} 的已授权应用`,
		subtitleFallback: '管理已授权应用',
		logoutAll: '退出所有会话',
		loggedIn: '登录成功，这是你当前的授权状态。',
		loading: '正在加载已授权应用…',
		noAuthorizations: '还没有应用获得授权。下次应用请求访问时会在这里出现。',
		lastAuthorized: (time: string) => `最近授权：${time}`,
		revoke: '撤销',
		revokeLabel: (client: string) => `撤销 ${client} 的授权`,
		bindingsTitle: '已绑定的游戏账号',
		noBindings: '还没有绑定游戏账号。绑定后，授权应用才能读取你的数据。',
		lastRefreshed: (time: string) => `最近刷新 ${time}`,
		unbind: '解除',
		unbindLabel: (connector: string) => `解除与 ${connector} 的绑定`,
		unbindAll: '解除全部绑定',
		cascadePartial: (count: number) =>
			`${count} 个绑定未能在上游撤销，已保留以便重试。`,
		notConnected: '尚未连接，连接后才能读取你在该服务的数据。',
		connect: '连接',
		connectLabel: (upstream: string) => `连接 ${upstream}`,
		backHome: '返回首页',
		identitiesTitle: '登录方式',
		identitiesHint: '这些登录方式都能进入同一个账号，至少保留一个。',
		noIdentities: '这个账号还没有登录方式。',
		identityAdded: '已添加新的登录方式。',
		identityDetach: '移除',
		identityDetachLabel: (issuer: string) => `移除来自 ${issuer} 的登录方式`,
		identityLastOne: '这是唯一的登录方式，移除后账号将无法登录。要离开请用「注销账号」。',
		identityAdd: '添加登录方式',
		identityConflict: '这个登录方式已绑定到另一个账号。本服务不合并账号：请先登出，用那个账号登录并移除它，再回到这里添加。',
		identityIssuer: (issuer: string) => issuer.replace(/^https?:\/\//, '').replace(/\/$/, ''),
		dangerTitle: '危险操作',
		dangerDeleteHint:
			'注销会删除账号与全部授权、绑定、会话。上游授权会先被撤销；任一上游无法确认时会中止，不删任何东西。',
		dangerTypeName: (name: string) => `输入「${name}」以确认`,
		dangerDelete: '注销账号',
		dangerDeleting: '正在注销…',
		dangerBlocked: '有上游授权未能撤销，账号未删除。请稍后重试。',
		bindingStatus: {
			active: { label: '已连接', hint: '' },
			pending: { label: '待确认', hint: '游戏账号还没有完成绑定。' },
			needsReauth: { label: '需要重新授权', hint: '游戏账号的访问凭据已失效，重新绑定后才能读取数据。' }
		}
	},

	about: {
		title: '关于 Re0Auth',
		account: '账号与授权'
	},


	admin: {
		title: '管理后台',
		nav: {
			overview: '总览',
			clients: '客户端',
			users: '用户',
			bindings: '绑定',
			audit: '审计',
			connectors: '连接器'
		},
		checking: '正在确认权限…',
		forbiddenTitle: '需要管理员权限',
		forbiddenBody: '当前账号不是管理员，无法使用管理后台。',
		loginTitle: '请先登录',
		loginBody: '管理后台只对已登录的管理员开放。',
		loginAction: '去登录',
		notConfigured: '这个实例没有启用管理接口。',
		loadFailed: '读取失败，请稍后重试。',
		stats: {
			title: '总览',
			subtitle: '实例的账号、客户端、绑定与审计规模。',
			users: '用户',
			clients: '客户端',
			activeBindings: '活跃绑定',
			auditRecords: '审计记录'
		},
		retry: '重试',
		loadMore: '加载更多',
		empty: '没有数据。',
		loading: '正在加载…',
		copy: '复制',
		copied: '已复制',
		copyFailed: '复制失败，请手动选择',
		close: '关闭',
		cancel: '取消',
		save: '保存',
		create: '新建',
		edit: '编辑',
		confirm: '确认',
		id: 'ID',
		time: '时间',
		clients: {
			title: '客户端',
			subtitle: '接入本服务的下游应用。新建与轮换时，secret 只显示一次。',
			newClient: '新建客户端',
			name: '名称',
			redirectUris: '回调地址',
			redirectUrisHint: '每行一个，必须与应用登记的值完全一致',
			allowedScopes: '允许的权限',
			allowedScopesHint: '每行一个 scope',
			confidential: '机密客户端（签发 secret）',
			rawAccess: '允许原始视图',
			status: '状态',
			hasSecret: '已设置 secret',
			noSecret: '公开客户端',
			createdAt: '创建时间',
			updatedAt: '更新时间',
			rotate: '轮换 secret',
			rotateConfirm: '旧 secret 会立即失效，正在使用它的应用会立刻中断。继续？',
			secretTitle: '请现在保存 secret',
			secretWarning: '关闭后无法再次查看。丢失只能重新轮换。',
			action: '操作',
			createFailed: '创建失败：',
			updateFailed: '保存失败：',
			conflict: '这条记录已被他人修改，已重新读取，请核对后再保存。'
		},
		users: {
			title: '用户',
			subtitle: '角色与封禁都会写入审计。不能降级或封禁自己，也不能动最后一个管理员。',
			role: '角色',
			status: '状态',
			displayName: '显示名',
			createdAt: '创建时间',
			roleChanged: '角色已更新。',
			roleFailed: '修改失败：',
			ban: '封禁',
			unban: '解封',
			banConfirm: '封禁会立即撤销该账号的全部会话，并拒绝其登录与网关读取。继续？',
			banned: '已封禁。',
			unbanned: '已解封。',
			statusFailed: '状态修改失败：'
		},
		userStatus: {
			active: '正常',
			banned: '已封禁'
		},
		bindings: {
			title: '绑定',
			subtitle: '按用户、连接器或状态过滤；撤销属于管理员级拉闸，会写入审计。',
			user: '用户 ID',
			connector: '连接器',
			status: '状态',
			upstreamUser: '上游用户',
			lastRefreshed: '最近刷新',
			revoke: '撤销',
			revokeConfirm: '撤销后该用户需要重新连接上游才能读取数据。继续？',
			revoked: '已撤销。',
			revokeFailed: '撤销失败：'
		},
		audit: {
			title: '审计',
			subtitle: '只读。按动作、档位与时间过滤；request_id 可用来关联客户端报告。',
			actor: '操作者 ID',
			client: '客户端 ID',
			action: '动作',
			actionHint: '例如 binding_revoked',
			tier: '档位',
			from: '起始时间',
			to: '结束时间',
			apply: '查询',
			reset: '清空条件',
			outcome: '结果',
			severity: '严重度',
			detail: '详情'
		},
		connectors: {
			title: '连接器',
			subtitle: '配置是权威来源，这里只读。资源决定了网关可访问的路径与所需 scope。',
			baseUrl: '上游地址',
			privateNet: '允许私网',
			resources: '资源',
			resourceName: '名称',
			resourcePath: '路径',
			resourceScope: '所需 scope',
			resourceMethod: '方法',
			resourceIdempotent: '可重试'
		},
		status: {
			pending: '待批准',
			approved: '已批准',
			suspended: '已暂停',
			revoked: '已撤销',
			active: '已激活',
			needs_reauth: '需重新授权'
		},
		role: {
			admin: '管理员',
			user: '普通用户'
		},
		tier: {
			fact: '安全事实',
			telemetry: '访问流水'
		},
		outcome: {
			success: '成功',
			failure: '失败',
			denied: '拒绝'
		},
		severity: {
			info: '提示',
			warning: '警告',
			critical: '严重'
		}
	},
	errors: {
		requestFailed: '请求失败',
		fallback: '请求失败，请稍后重试。',
		missingCsrf: '缺少 CSRF 凭据，请重新登录。',
		checkFailed: '安全校验失败，请刷新页面后重试。',
		authorizationGone: '这条授权已不存在，刷新页面后再试。'
	}
} as const;
