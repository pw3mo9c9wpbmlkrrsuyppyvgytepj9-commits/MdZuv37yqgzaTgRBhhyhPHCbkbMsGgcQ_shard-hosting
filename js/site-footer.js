/**
 * Appends the global site footer (Bisect-style columns) once per page.
 */
(function () {
	if (document.querySelector(".site-footer")) {
		return;
	}
	document.body.insertAdjacentHTML(
		"beforeend",
		`<footer class="site-footer">
  <div class="site-footer-inner">
    <div class="site-footer-grid">
      <div class="site-footer-col">
        <h4>Company</h4>
        <a href="/about_us.html">About us</a>
        <a href="/faq.html">FAQ</a>
      </div>
      <div class="site-footer-col">
        <h4>Support</h4>
        <a href="/support.html">Help center</a>
        <a href="/support/discord_hosting.html">Discord hosting</a>
        <a href="https://discord.gg/2ad8RrHa8j" target="_blank" rel="noopener noreferrer">Contact us</a>
      </div>
      <div class="site-footer-col">
        <h4>Legal</h4>
        <a href="/privacy_policy.html">Privacy policy</a>
        <a href="/terms_of_service.html">Terms of service</a>
      </div>
      <div class="site-footer-col">
        <h4>Social</h4>
        <div class="site-footer-social">
          <a href="https://discord.gg/2ad8RrHa8j" target="_blank" rel="noopener noreferrer">Discord</a>
        </div>
      </div>
    </div>
    <div class="site-footer-pay">Stripe · Mastercard · Robux</div>
    <p class="site-footer-copy">Copyright ${new Date().getFullYear()} · Shard Hosting. All rights reserved.</p>
  </div>
</footer>`
	);
})();
