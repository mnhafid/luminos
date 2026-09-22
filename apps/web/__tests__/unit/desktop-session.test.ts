import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import {
	createDesktopRedirectPage,
	desktopSessionRequestQuerySchema,
	isSignInBypassed,
	serializeStateForScript,
} from "@/lib/desktop-session";

describe("sign-in bypass gate", () => {
	it.each([
		[true, "development", true],
		[true, "test", true],
		[true, "production", false],
		[false, "development", false],
	])("bypass=%s in %s → %s", (bypass, nodeEnv, expected) => {
		expect(isSignInBypassed(bypass, nodeEnv)).toBe(expected);
	});
});

describe("desktop session request query", () => {
	it("defaults to a session token", () => {
		const result = desktopSessionRequestQuerySchema.safeParse({});
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.type).toBe("session");
	});

	it("ignores legacy loopback `port`/`platform` params from older desktop builds", async () => {
		const app = new Hono().get(
			"/request",
			zValidator("query", desktopSessionRequestQuerySchema),
			(c) => c.json(c.req.valid("query")),
		);
		const res = await app.request(
			`/request?type=api_key&platform=desktop&port=${encodeURIComponent("pwn@192.168.0.25:8999")}`,
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ type: "api_key" });
	});

	it("accepts format=json for the desktop bypass fetch", () => {
		const result = desktopSessionRequestQuerySchema.safeParse({
			format: "json",
		});
		expect(result.success && result.data.format).toBe("json");
	});
});

describe("desktop redirect page escaping", () => {
	it("neutralises a </script> breakout in the embedded JSON state", () => {
		const serialized = serializeStateForScript({
			deepLinkUrl: "cap-desktop://signin?x=</script><script>alert(1)//",
		});
		expect(serialized).not.toContain("<");
		expect(serialized).not.toContain(">");
		expect(JSON.parse(serialized)).toEqual({
			deepLinkUrl: "cap-desktop://signin?x=</script><script>alert(1)//",
		});
	});

	it("renders exactly one script element for a hostile deep link", () => {
		const html = createDesktopRedirectPage(
			"cap-desktop://signin?x=</script><script>alert(document.domain)//",
		);
		expect(html.match(/<script/g)).toHaveLength(1);
		expect(html.match(/<\/script/g)).toHaveLength(1);
		expect(html).not.toContain("</script><script>");
	});
});
