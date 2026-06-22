const app = require("../server.js");

/**
 * Vercel catch-all under /api/* — restore full /api/... path for Express routes.
 */
module.exports = (req, res) => {
	const pathParam = req.query?.path;
	if (pathParam !== undefined) {
		const segments = Array.isArray(pathParam) ? pathParam : [pathParam];
		const search = new URLSearchParams();
		for (const [key, value] of Object.entries(req.query)) {
			if (key === "path") {
				continue;
			}
			if (Array.isArray(value)) {
				for (const item of value) {
					search.append(key, item);
				}
			} else if (value != null) {
				search.append(key, value);
			}
		}
		const qs = search.toString();
		req.url = `/api/${segments.join("/")}${qs ? `?${qs}` : ""}`;
	}
	return app(req, res);
};
