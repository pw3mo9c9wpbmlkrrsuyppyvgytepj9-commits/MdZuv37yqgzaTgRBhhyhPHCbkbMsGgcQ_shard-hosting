/**
 * Development warning banner — index, dashboard, login.
 * Dismiss hides it for the current page only; it reappears on every new page.
 */
(function () {
	const DISCORD_URL = "https://discord.gg/2ad8RrHa8j";

	function syncBannerOffset(banner) {
		const height = banner.offsetHeight;
		document.documentElement.style.setProperty("--dev-banner-height", `${height}px`);
	}

	const banner = document.createElement("aside");
	banner.className = "dev-banner";
	banner.setAttribute("role", "alert");
	banner.setAttribute("aria-live", "polite");
	banner.innerHTML = `<p>This website is in development, there will be bugs and issues, please report them in our <a href="${DISCORD_URL}" target="_blank" rel="noopener noreferrer">Discord</a>.</p><button type="button" class="dev-banner-dismiss" aria-label="Dismiss development notice">×</button>`;

	document.body.insertBefore(banner, document.body.firstChild);
	document.body.classList.add("dev-banner-visible");
	syncBannerOffset(banner);

	window.addEventListener("resize", () => syncBannerOffset(banner));

	banner.querySelector(".dev-banner-dismiss").addEventListener("click", () => {
		banner.remove();
		document.body.classList.remove("dev-banner-visible");
		document.documentElement.style.removeProperty("--dev-banner-height");
	});
})();
