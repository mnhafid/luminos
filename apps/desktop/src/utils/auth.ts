import { createMutation } from "@tanstack/solid-query";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { fetch } from "@tauri-apps/plugin-http";
import * as shell from "@tauri-apps/plugin-shell";
import { z } from "zod";
import { authStore, generalSettingsStore } from "~/store";
import type { AuthStore } from "~/utils/tauri";
import { identifyUser, trackEvent } from "./analytics";
import { clientEnv } from "./env";
import { commands } from "./tauri";

const paramsValidator = z.union([
	z.object({
		type: z.literal("api_key"),
		api_key: z.string(),
		user_id: z.string(),
	}),
	z.object({
		token: z.string(),
		user_id: z.string(),
		expires: z.coerce.number(),
	}),
]);

type AuthParams = z.infer<typeof paramsValidator>;

const bypassSignIn = import.meta.env.VITE_BYPASS_SIGNIN === "true";

export async function signInWithoutBrowser() {
	if (!bypassSignIn || (await authStore.get())) return false;
	const url = await createSessionRequestUrl();
	url.searchParams.set("format", "json");
	// Tauri's fetch, not the webview's: the dev webview origin (localhost:3002)
	// is not in the server's CORS allowlist, so a browser fetch is blocked.
	const res = await fetch(url);
	if (!res.ok || !res.headers.get("content-type")?.includes("json")) {
		console.warn(
			`Sign-in bypass unavailable: ${res.status} ${res.headers.get("content-type")}`,
		);
		return false;
	}
	await processAuthData(paramsValidator.parse(await res.json()), {
		upgraded: true,
		manual: true,
		last_checked: Math.floor(Date.now() / 1000),
	});
	return true;
}

export function createSignInMutation() {
	return createMutation(() => ({
		mutationFn: async (abort: AbortController) => {
			if (bypassSignIn && (await signInWithoutBrowser())) return;

			const deepLink = await startDeepLinkSession(abort.signal);

			await shell.open((await createSessionRequestUrl()).toString());

			const res = await deepLink.complete;
			await deepLink.dispose();
			if (abort.signal.aborted) throw new Error("Sign in aborted");
			if (res) await processAuthData(res);

			getCurrentWindow().setFocus();
		},
	}));
}

async function createSessionRequestUrl() {
	const serverUrl =
		(await generalSettingsStore.get())?.serverUrl ?? clientEnv.VITE_SERVER_URL;
	return new URL("/api/desktop/session/request?type=api_key", serverUrl);
}

async function startDeepLinkSession(signal: AbortSignal) {
	let settled = false;
	let stopListening: (() => void) | undefined;
	let resolvePromise: (data: AuthParams | null) => void = () => {};

	const complete = new Promise<AuthParams | null>((resolve) => {
		resolvePromise = resolve;
	});

	const settle = (value: AuthParams | null) => {
		if (settled) return;
		settled = true;
		resolvePromise(value);
	};

	stopListening = await onOpenUrl(async (urls) => {
		for (const urlString of urls) {
			if (signal.aborted) return;
			settle(parseAuthParams(new URL(urlString)));
		}
	});

	const dispose = async () => {
		stopListening?.();
		stopListening = undefined;
		settle(null);
	};

	signal.addEventListener("abort", () => void dispose(), { once: true });

	return { complete, dispose };
}

function parseAuthParams(url: URL) {
	return paramsValidator.parse(
		[...url.searchParams].reduce(
			(acc, [key, value]) => {
				acc[key] = value;
				return acc;
			},
			{} as Record<string, string>,
		),
	);
}

async function processAuthData(
	data: AuthParams,
	plan: AuthStore["plan"] = null,
) {
	identifyUser(data.user_id);
	trackEvent("user_signed_in", { platform: "desktop" });

	await authStore.set({
		secret:
			"api_key" in data
				? { api_key: data.api_key }
				: { token: data.token, expires: data.expires },
		user_id: data.user_id,
		plan,
	});

	await commands.updateAuthPlan();
}
