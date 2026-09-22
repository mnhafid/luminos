import { z } from "zod";

export const desktopSessionRequestQuerySchema = z.object({
	format: z.literal("json").optional(),
	type: z
		.union([z.literal("session"), z.literal("api_key")])
		.default("session"),
});

export function isSignInBypassed(bypass: boolean, nodeEnv: string) {
	return bypass && nodeEnv !== "production";
}

export function serializeStateForScript(value: unknown) {
	// Escape characters that could break out of an inline <script> (or split the
	// script via U+2028/U+2029) into their \uXXXX JSON form so the template can
	// never become an XSS sink if an upstream value changes.
	return (JSON.stringify(value) ?? "null").replace(
		/[<>&\u2028\u2029]/g,
		(ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`,
	);
}

export function createDesktopRedirectPage(deepLinkUrl: string) {
	const state = serializeStateForScript({ deepLinkUrl });

	return `<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate" />
		<meta http-equiv="Pragma" content="no-cache" />
		<title>Open Cap</title>
		<style>
			:root {
				color-scheme: light;
				font-family: Inter, "Segoe UI", sans-serif;
			}

			body {
				margin: 0;
				min-height: 100vh;
				display: grid;
				place-items: center;
				background: linear-gradient(180deg, #f6f8fc 0%, #eef3ff 100%);
				color: #111827;
			}

			main {
				width: min(440px, calc(100vw - 32px));
				padding: 32px 28px;
				border-radius: 24px;
				background: rgba(255, 255, 255, 0.92);
				box-shadow: 0 24px 60px rgba(15, 23, 42, 0.12);
				text-align: center;
			}

			h1 {
				margin: 0 0 12px;
				font-size: 28px;
				line-height: 1.1;
			}

			p {
				margin: 0;
				font-size: 16px;
				line-height: 1.5;
				color: #4b5563;
			}

			.actions {
				margin-top: 24px;
				display: grid;
				gap: 12px;
			}

			button {
				width: 100%;
				border: 0;
				border-radius: 14px;
				padding: 14px 16px;
				font: inherit;
				font-weight: 600;
				cursor: pointer;
				text-decoration: none;
				box-sizing: border-box;
			}

			button {
				background: #2563eb;
				color: white;
			}

			#status {
				margin-top: 18px;
				font-size: 14px;
				color: #6b7280;
			}
		</style>
	</head>
	<body>
		<main>
			<h1>Opening Cap</h1>
			<p>If Cap does not open automatically, try the button below.</p>
			<div class="actions">
				<button id="open-cap" type="button">Open Cap</button>
			</div>
			<p id="status">Opening the Cap desktop app...</p>
		</main>
		<script>
			const { deepLinkUrl } = ${state};
			const openCap = () => {
				window.location.href = deepLinkUrl;
			};
			document.getElementById("open-cap").addEventListener("click", openCap);
			openCap();
		</script>
	</body>
</html>`;
}
