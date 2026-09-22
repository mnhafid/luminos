use std::{io::IsTerminal, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    OutputFormat,
    credentials::{self, AgentCredentialSource, StoredAgentCredential},
    resolve_format, write_json,
};

#[derive(Args)]
pub struct LoginArgs {
    #[arg(long, value_enum, default_value_t = LoginProfile::Creator)]
    profile: LoginProfile,
    #[arg(long)]
    no_open: bool,
    #[arg(
        long,
        help = "Allow a permission-restricted file fallback on macOS or Linux when the OS credential store is unavailable"
    )]
    allow_file_credential: bool,
    #[arg(long, default_value_t = 300)]
    timeout: u64,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum LoginProfile {
    Creator,
    Admin,
    Full,
}

impl LoginProfile {
    const fn scopes(self) -> &'static str {
        const CREATOR: &str = "caps:read caps:comment caps:write profile:read profile:write caps:upload caps:process caps:delete library:read library:write analytics:read notifications:read notifications:write";
        const ADMIN: &str = "caps:read caps:comment caps:write profile:read profile:write caps:upload caps:process caps:delete library:read library:write analytics:read organizations:read organizations:manage organizations:members notifications:read notifications:write integrations:read integrations:write billing:read billing:write";
        const FULL: &str = "caps:read caps:comment caps:write profile:read profile:write caps:upload caps:process caps:delete library:read library:write analytics:read organizations:read organizations:manage organizations:members notifications:read notifications:write integrations:read integrations:write billing:read billing:write developer:read developer:write developer:secrets";
        match self {
            Self::Creator => CREATOR,
            Self::Admin => ADMIN,
            Self::Full => FULL,
        }
    }
}

#[derive(Args)]
pub struct LogoutArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginResult {
    authenticated: bool,
    server: String,
    expires_at: String,
    scopes: Vec<String>,
    storage: credentials::AgentCredentialStorage,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogoutResult {
    authenticated: bool,
    revoked: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenRequest<'a> {
    code: &'a str,
    code_verifier: &'a str,
    redirect_uri: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    access_token: String,
    expires_at: String,
    scopes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeResponse {
    revoked: bool,
}

fn random_base64url() -> String {
    let first = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(first.as_bytes());
    bytes[16..].copy_from_slice(second.as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn api_error(status: reqwest::StatusCode, body: &str) -> String {
    let value = serde_json::from_str::<serde_json::Value>(body).ok();
    let code = value
        .as_ref()
        .and_then(|value| value.get("code"))
        .and_then(serde_json::Value::as_str);
    let message = value
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(serde_json::Value::as_str);
    match (code, message) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        _ => format!("Cap returned HTTP {status}"),
    }
}

fn auth_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "Failed to initialize secure authentication".to_string())
}

const fn is_agent_credential_source(source: AgentCredentialSource) -> bool {
    matches!(
        source,
        AgentCredentialSource::Env | AgentCredentialSource::Keyring | AgentCredentialSource::File
    )
}

const fn should_delete_persistent_credentials(source: AgentCredentialSource) -> bool {
    matches!(
        source,
        AgentCredentialSource::Keyring | AgentCredentialSource::File
    )
}

const OOB_REDIRECT_URI: &str = "urn:ietf:wg:oauth:2.0:oob";

async fn read_authorization_code(timeout: Duration) -> Result<String, String> {
    eprintln!("Paste the authorization code shown in the browser, then press Enter:");
    let line = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map(|_| line)
                .map_err(|error| format!("Failed to read the authorization code: {error}"))
        }),
    )
    .await
    .map_err(|_| "Timed out waiting for the authorization code".to_string())?
    .map_err(|error| error.to_string())??;
    let code = line.trim();
    if code.is_empty() {
        return Err("No authorization code was provided".to_string());
    }
    Ok(code.to_string())
}

impl LoginArgs {
    pub async fn run(self, global_json: bool) -> Result<(), String> {
        let format = resolve_format(global_json, self.format);
        let result = self.run_inner(format).await;
        if let Err(error) = &result
            && format == OutputFormat::Json
        {
            let _ = write_json(&serde_json::json!({ "error": error }));
        }
        result
    }

    async fn run_inner(self, format: OutputFormat) -> Result<(), String> {
        if self.timeout == 0 || self.timeout > 900 {
            return Err("--timeout must be between 1 and 900 seconds".to_string());
        }
        let verifier = random_base64url();
        let state = random_base64url();
        let server = credentials::agent_server_url()?;
        let mut authorize_url = Url::parse(&format!("{server}/cli/authorize"))
            .map_err(|_| "CAP_SERVER_URL is not a valid URL".to_string())?;
        authorize_url
            .query_pairs_mut()
            .append_pair("client_id", "cap-cli")
            .append_pair("redirect_uri", OOB_REDIRECT_URI)
            .append_pair("response_type", "code")
            .append_pair("state", &state)
            .append_pair("code_challenge", &code_challenge(&verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("scope", self.profile.scopes());

        if self.no_open {
            eprintln!("Open this URL to authorize Cap CLI:\n{authorize_url}");
        } else if let Err(error) = open::that(authorize_url.as_str()) {
            eprintln!("Could not open a browser ({error}). Open this URL:\n{authorize_url}");
        }

        let code = read_authorization_code(Duration::from_secs(self.timeout)).await?;
        let client = auth_client()?;
        let response = client
            .post(format!("{server}/api/v1/auth/token"))
            .json(&TokenRequest {
                code: &code,
                code_verifier: &verifier,
                redirect_uri: OOB_REDIRECT_URI,
            })
            .send()
            .await
            .map_err(|error| format!("Failed to exchange the authorization code: {error}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| format!("Failed to read the token response: {error}"))?;
        if !status.is_success() {
            return Err(api_error(status, &body));
        }
        let token: TokenResponse =
            serde_json::from_str(&body).map_err(|_| "Cap returned an invalid token".to_string())?;
        let storage = credentials::store_agent(
            &StoredAgentCredential {
                access_token: token.access_token.clone(),
                expires_at: token.expires_at.clone(),
                scopes: token.scopes.clone(),
                server: server.clone(),
            },
            self.allow_file_credential,
        );
        let storage = match storage {
            Ok(storage) => storage,
            Err(error) => {
                let _ = client
                    .post(format!("{server}/api/v1/auth/revoke"))
                    .bearer_auth(&token.access_token)
                    .send()
                    .await;
                return Err(error);
            }
        };
        let result = LoginResult {
            authenticated: true,
            server,
            expires_at: token.expires_at,
            scopes: token.scopes,
            storage,
        };
        match format {
            OutputFormat::Json => write_json(&result),
            OutputFormat::Text => {
                println!("Cap CLI is authorized.");
                println!("server: {}", result.server);
                println!("expires: {}", result.expires_at);
                Ok(())
            }
        }
    }
}

impl LogoutArgs {
    pub async fn run(self, global_json: bool) -> Result<(), String> {
        let format = resolve_format(global_json, self.format);
        let result = self.run_inner(format).await;
        if let Err(error) = &result
            && format == OutputFormat::Json
        {
            let _ = write_json(&serde_json::json!({ "error": error }));
        }
        result
    }

    async fn run_inner(self, format: OutputFormat) -> Result<(), String> {
        let credentials = credentials::resolve_agent()?;
        if !is_agent_credential_source(credentials.source) {
            return Err(
                "No Cap CLI agent credential is stored. A legacy CAP_API_KEY and Cap Desktop login are not changed by `cap auth logout`."
                    .to_string(),
            );
        }
        let revocable = credentials::is_agent_api_key(&credentials.access_token);
        let revoked = if revocable {
            let response = auth_client()?
                .post(format!("{}/api/v1/auth/revoke", credentials.server))
                .bearer_auth(&credentials.access_token)
                .send()
                .await
                .map_err(|error| format!("Failed to revoke the Cap credential: {error}"))?;
            if response.status().is_success() {
                response
                    .json::<RevokeResponse>()
                    .await
                    .map_err(|_| "Cap returned an invalid revocation response".to_string())?
                    .revoked
            } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                false
            } else {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(api_error(status, &body));
            }
        } else {
            false
        };
        if should_delete_persistent_credentials(credentials.source) {
            credentials::delete_agent()?;
        }
        let result = LogoutResult {
            authenticated: false,
            revoked,
        };
        match format {
            OutputFormat::Json => write_json(&result),
            OutputFormat::Text => {
                if credentials.source == AgentCredentialSource::Env {
                    println!("Cap CLI environment credential revoked.");
                    if std::io::stdin().is_terminal() {
                        let variable =
                            credentials::agent_env_var_name().unwrap_or("CAP_AGENT_TOKEN");
                        println!("Unset {variable} to remove it from this shell.");
                    }
                } else {
                    println!("Cap CLI credential removed.");
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_values_have_the_required_shape() {
        let verifier = random_base64url();
        assert_eq!(verifier.len(), 43);
        assert_eq!(code_challenge(&verifier).len(), 43);
    }

    #[test]
    fn login_profiles_are_incremental() {
        let creator = LoginProfile::Creator.scopes();
        let admin = LoginProfile::Admin.scopes();
        let full = LoginProfile::Full.scopes();
        assert!(creator.contains("caps:upload"));
        assert!(!creator.contains("organizations:manage"));
        assert!(admin.contains("organizations:manage"));
        assert!(!admin.contains("developer:secrets"));
        assert!(full.contains("developer:secrets"));
    }

    #[test]
    fn errors_never_echo_unknown_response_bodies() {
        let error = api_error(reqwest::StatusCode::BAD_GATEWAY, "secret upstream body");
        assert_eq!(error, "Cap returned HTTP 502 Bad Gateway");
        assert!(!error.contains("secret"));
    }

    #[test]
    fn logout_never_claims_legacy_credentials() {
        assert!(is_agent_credential_source(AgentCredentialSource::Env));
        assert!(is_agent_credential_source(AgentCredentialSource::Keyring));
        assert!(is_agent_credential_source(AgentCredentialSource::File));
        assert!(!is_agent_credential_source(
            AgentCredentialSource::LegacyEnv
        ));
        assert!(!is_agent_credential_source(AgentCredentialSource::Desktop));
        assert!(!should_delete_persistent_credentials(
            AgentCredentialSource::Env
        ));
        assert!(should_delete_persistent_credentials(
            AgentCredentialSource::Keyring
        ));
        assert!(should_delete_persistent_credentials(
            AgentCredentialSource::File
        ));
    }
}
