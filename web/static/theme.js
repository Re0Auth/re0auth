(function () {
	var stored = localStorage.getItem('theme');
	var mode = stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'system';
	var query = window.matchMedia('(prefers-color-scheme: dark)');

	function resolve(value) {
		return value === 'system' ? (query.matches ? 'dark' : 'light') : value;
	}

	document.documentElement.dataset.themeMode = mode;
	document.documentElement.dataset.theme = resolve(mode);

	query.addEventListener('change', function () {
		if (document.documentElement.dataset.themeMode === 'system') {
			document.documentElement.dataset.theme = query.matches ? 'dark' : 'light';
		}
	});
})();
