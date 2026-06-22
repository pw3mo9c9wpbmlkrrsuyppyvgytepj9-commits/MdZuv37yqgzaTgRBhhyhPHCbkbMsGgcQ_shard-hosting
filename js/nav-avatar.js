/**
 * Sets #nav-avatar from /api/me when logged in. Safe on public pages (no-op if 401).
 */
(function () {
	function run() {
		const img = document.getElementById("nav-avatar");
		if (!img) {
			return;
		}
		fetch("/api/me", { credentials: "same-origin" })
			.then((r) => (r.ok ? r.json() : null))
			.then((data) => {
				if (data && data.user && data.user.avatar_data_url) {
					img.src = data.user.avatar_data_url;
				}
			})
			.catch(() => {});
	}
	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", run);
	} else {
		run();
	}
})();
