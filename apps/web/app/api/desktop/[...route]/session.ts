import { db } from "@cap/database";
import { decodeSessionToken } from "@cap/database/auth/auth-options";
import { getCurrentUser } from "@cap/database/auth/session";
import { nanoId } from "@cap/database/helpers";
import {
	authApiKeys,
	organizationMembers,
	organizations,
	users,
} from "@cap/database/schema";
import { serverEnv } from "@cap/env";
import { Organisation, User } from "@cap/web-domain";
import { zValidator } from "@hono/zod-validator";
import { asc } from "drizzle-orm";
import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import {
	createDesktopRedirectPage,
	desktopSessionRequestQuerySchema,
	isSignInBypassed,
} from "@/lib/desktop-session";

export const app = new Hono();

app.get(
	"/request",
	zValidator("query", desktopSessionRequestQuerySchema),
	async (c) => {
		const { type, format } = c.req.valid("query");

		const secret = serverEnv().NEXTAUTH_SECRET;

		const url = new URL(c.req.url);

		const redirectOrigin = getDeploymentOrigin();

		const loginRedirectUrl = new URL(`${redirectOrigin}/login`);
		loginRedirectUrl.searchParams.set(
			"next",
			new URL(`${redirectOrigin}${url.pathname}${url.search}`).toString(),
		);

		const user = (await getCurrentUser()) ?? (await getLocalDevelopmentUser());
		if (!user) return c.redirect(loginRedirectUrl);

		let data:
			| { type: "token"; token: string; expires: string }
			| { type: "api_key"; api_key: string };

		if (type === "session" && !("local" in user)) {
			const token = getCookie(c, "next-auth.session-token");
			if (token === undefined) return c.redirect(loginRedirectUrl);

			const decodedToken = await decodeSessionToken({ token, secret });

			if (!decodedToken) return c.redirect(loginRedirectUrl);

			data = {
				type: "token",
				token,
				expires: String(decodedToken.exp),
			};
		} else {
			const id = crypto.randomUUID();
			await db()
				.insert(authApiKeys)
				.values({ id, userId: user.id, source: "desktop" });

			data = { type: "api_key", api_key: id };
		}

		if (format === "json") return c.json({ ...data, user_id: user.id });

		const params = new URLSearchParams({ ...data, user_id: user.id });

		return new Response(
			createDesktopRedirectPage(`cap-desktop://signin?${params}`),
			{
				headers: {
					"Content-Type": "text/html; charset=utf-8",
					"Cache-Control": "no-store, no-cache, must-revalidate",
					Pragma: "no-cache",
				},
			},
		);
	},
);

async function getLocalDevelopmentUser() {
	if (!isSignInBypassed(serverEnv().CAP_BYPASS_SIGNIN, serverEnv().NODE_ENV)) {
		return null;
	}
	const [user] = await db()
		.select({ id: users.id })
		.from(users)
		.orderBy(asc(users.created_at))
		.limit(1);
	if (user) return { ...user, local: true };

	const userId = User.UserId.make(nanoId());
	const organizationId = Organisation.OrganisationId.make(nanoId());
	await db().transaction(async (tx) => {
		await tx.insert(users).values({
			id: userId,
			email: "dev@localhost",
			name: "Dev",
			emailVerified: new Date(),
			activeOrganizationId: organizationId,
			defaultOrgId: organizationId,
		});
		await tx
			.insert(organizations)
			.values({ id: organizationId, ownerId: userId, name: "My Organization" });
		await tx
			.insert(organizationMembers)
			.values({ id: nanoId(), organizationId, userId, role: "owner" });
	});
	return { id: userId, local: true };
}

function getDeploymentOrigin() {
	const webUrl = serverEnv().WEB_URL;
	const vercelEnv = serverEnv().VERCEL_ENV;

	if (!vercelEnv || vercelEnv === "production") {
		return webUrl;
	}

	if (vercelEnv === "preview") {
		const branchHost = serverEnv().VERCEL_BRANCH_URL_HOST;
		if (branchHost?.endsWith(".vercel.app")) {
			return `https://${branchHost}`;
		}
	}

	return webUrl;
}
