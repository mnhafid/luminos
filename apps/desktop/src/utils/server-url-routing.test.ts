import { describe, expect, it } from "vitest";
import { resolveServerRequestPath } from "./server-url-routing";

describe("server-url-routing", () => {
	it("does not rewrite Cap Cloud API requests for the default origin", () => {
		const path = "https://cap.so/api/desktop/user/profile";

		expect(
			resolveServerRequestPath(path, "https://cap.so", "https://cap.so"),
		).toBe(path);
	});

	it("does not rewrite Cap Cloud API requests for equivalent origins", () => {
		const path = "https://cap.so/api/desktop/user/profile";

		expect(
			resolveServerRequestPath(path, "https://cap.so/", "https://cap.so"),
		).toBe(path);
	});

	it("rewrites packaged API requests to custom origins", () => {
		expect(
			resolveServerRequestPath(
				"https://cap.so/api/desktop/user/profile?refresh=true#profile",
				"https://cap-web-production-7301.up.railway.app",
				"https://cap.so",
			),
		).toBe(
			"https://cap-web-production-7301.up.railway.app/api/desktop/user/profile?refresh=true#profile",
		);
	});

	it("does not rewrite external API requests", () => {
		const path = "https://l.cap.so/api/license/activate";

		expect(
			resolveServerRequestPath(
				path,
				"https://cap-web-production-7301.up.railway.app",
				"https://cap.so",
			),
		).toBe(path);
	});
});
