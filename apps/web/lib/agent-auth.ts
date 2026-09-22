import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Agent } from "@cap/web-domain";

export const agentScopes = [
	"caps:read",
	"caps:comment",
	"caps:write",
	"profile:read",
	"profile:write",
	"caps:upload",
	"caps:process",
	"caps:delete",
	"library:read",
	"library:write",
	"analytics:read",
	"organizations:read",
	"organizations:manage",
	"organizations:members",
	"notifications:read",
	"notifications:write",
	"integrations:read",
	"integrations:write",
	"billing:read",
	"billing:write",
	"developer:read",
	"developer:write",
	"developer:secrets",
] as const satisfies readonly Agent.AgentScope[];

// Mirrors the CLI's `cap auth login --profile` scope sets (apps/cli/src/agent_auth.rs) so a key
// minted from the dashboard grants exactly what the equivalent browser login would.
const creatorProfileScopes: Agent.AgentScope[] = [
	"caps:read",
	"caps:comment",
	"caps:write",
	"profile:read",
	"profile:write",
	"caps:upload",
	"caps:process",
	"caps:delete",
	"library:read",
	"library:write",
	"analytics:read",
	"notifications:read",
	"notifications:write",
];

const adminProfileScopes: Agent.AgentScope[] = [
	...creatorProfileScopes,
	"organizations:read",
	"organizations:manage",
	"organizations:members",
	"integrations:read",
	"integrations:write",
	"billing:read",
	"billing:write",
];

const fullProfileScopes: Agent.AgentScope[] = [
	...adminProfileScopes,
	"developer:read",
	"developer:write",
	"developer:secrets",
];

const canonicalScopeOrder = (scopes: Agent.AgentScope[]) =>
	agentScopes.filter((scope) => scopes.includes(scope));

export const agentScopeProfiles = {
	creator: canonicalScopeOrder(creatorProfileScopes),
	admin: canonicalScopeOrder(adminProfileScopes),
	full: canonicalScopeOrder(fullProfileScopes),
} as const;

export type AgentScopeProfile = keyof typeof agentScopeProfiles;

export const isAgentScopeProfile = (
	value: string,
): value is AgentScopeProfile => Object.hasOwn(agentScopeProfiles, value);

export type AgentAuthorizationRequest = {
	clientId: "cap-cli";
	redirectUri: string;
	state: string;
	codeChallenge: string;
	scopes: Agent.AgentScope[];
};

type AuthorizationParams = Record<string, string | string[] | undefined>;

const single = (value: string | string[] | undefined) =>
	typeof value === "string" ? value : null;

export const AGENT_OOB_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob";

export const isAgentOobRedirectUri = (value: string) =>
	value === AGENT_OOB_REDIRECT_URI;

export const isAgentState = (value: string) =>
	value.length >= 43 && value.length <= 128 && /^[A-Za-z0-9_-]+$/.test(value);

export const isAgentCodeChallenge = (value: string) =>
	value.length === 43 && /^[A-Za-z0-9_-]+$/.test(value);

export const isAgentCodeVerifier = (value: string) =>
	value.length >= 43 && value.length <= 128 && /^[A-Za-z0-9._~-]+$/.test(value);

export const parseAgentScopes = (value: string) => {
	const requested = value.split(" ").filter(Boolean);
	if (
		requested.length === 0 ||
		new Set(requested).size !== requested.length ||
		requested.some(
			(scope) => !agentScopes.includes(scope as Agent.AgentScope),
		) ||
		!requested.includes("caps:read")
	) {
		return null;
	}
	return agentScopes.filter((scope) => requested.includes(scope));
};

export const parseAgentAuthorizationRequest = (
	params: AuthorizationParams,
): AgentAuthorizationRequest | null => {
	const clientId = single(params.client_id);
	const redirectUri = single(params.redirect_uri);
	const responseType = single(params.response_type);
	const state = single(params.state);
	const codeChallenge = single(params.code_challenge);
	const codeChallengeMethod = single(params.code_challenge_method);
	const scope = single(params.scope);
	const scopes = scope ? parseAgentScopes(scope) : null;
	if (
		clientId !== "cap-cli" ||
		!redirectUri ||
		!isAgentOobRedirectUri(redirectUri) ||
		responseType !== "code" ||
		!state ||
		!isAgentState(state) ||
		!codeChallenge ||
		!isAgentCodeChallenge(codeChallenge) ||
		codeChallengeMethod !== "S256" ||
		!scopes
	) {
		return null;
	}
	return { clientId, redirectUri, state, codeChallenge, scopes };
};

export const hashAgentSecret = (value: string) =>
	createHash("sha256").update(value).digest("hex");

export const verifyAgentCodeChallenge = (
	verifier: string,
	challenge: string,
) => {
	if (!isAgentCodeVerifier(verifier) || !isAgentCodeChallenge(challenge)) {
		return false;
	}
	const actual = Buffer.from(
		createHash("sha256").update(verifier).digest("base64url"),
	);
	const expected = Buffer.from(challenge);
	return actual.length === expected.length && timingSafeEqual(actual, expected);
};

export const createAgentAuthorizationCode = () =>
	randomBytes(32).toString("base64url");

export const createAgentAccessToken = () =>
	`cap_cli_${randomBytes(32).toString("base64url")}`;
