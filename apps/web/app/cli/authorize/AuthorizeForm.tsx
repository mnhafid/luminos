"use client";

import { useActionState } from "react";
import type { AgentAuthorizationRequest } from "@/lib/agent-auth";

export type AuthorizeState = { code?: string; error?: string };

export function AuthorizeForm(props: {
	action: (
		previous: AuthorizeState,
		formData: FormData,
	) => Promise<AuthorizeState>;
	request: AgentAuthorizationRequest;
}) {
	const [state, formAction, pending] = useActionState(props.action, {});

	if (state.code) {
		return (
			<div className="mt-8 space-y-3">
				<p className="text-sm leading-6 text-gray-10">
					Paste this code into the terminal running cap auth login:
				</p>
				<code className="block select-all break-all rounded-lg bg-gray-2 px-4 py-3 font-mono text-sm text-gray-12">
					{state.code}
				</code>
			</div>
		);
	}

	return (
		<form action={formAction} className="mt-8 space-y-3">
			<input name="clientId" type="hidden" value={props.request.clientId} />
			<input
				name="redirectUri"
				type="hidden"
				value={props.request.redirectUri}
			/>
			<input name="state" type="hidden" value={props.request.state} />
			<input
				name="codeChallenge"
				type="hidden"
				value={props.request.codeChallenge}
			/>
			<input
				name="scope"
				type="hidden"
				value={props.request.scopes.join(" ")}
			/>
			{state.error && (
				<p className="text-sm text-red-11" role="alert">
					{state.error}
				</p>
			)}
			<button
				className="w-full rounded-lg bg-blue-9 px-4 py-3 text-sm font-medium text-white transition-colors hover:bg-blue-10 disabled:opacity-60"
				disabled={pending}
				type="submit"
			>
				Authorize
			</button>
			<a
				className="block w-full rounded-lg border border-gray-5 px-4 py-3 text-center text-sm font-medium text-gray-11 transition-colors hover:bg-gray-2"
				href="/"
			>
				Cancel
			</a>
		</form>
	);
}
