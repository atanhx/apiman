//! Local credential-injecting reverse proxy.
//!
//! Clients (apps, SDKs, AI agents) talk plain HTTP to 127.0.0.1 and never hold
//! the real key: apiman looks up the route, adds the secret to the outbound
//! request headers/query, and forwards it over HTTPS to the route's fixed
//! upstream only. Secrets are fetched from the session daemon per request, so
//! locking the vault immediately stops the proxy from authenticating.

use crate::daemon::get_cached_master_key;
use crate::runner::Masker;
use crate::storage::load_vault_with_key;
use crate::vault::{SecretRef, Vault, normalize_project};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const DEFAULT_PORT: u16 = 8787;
const SECRET_PLACEHOLDER: &str = "{secret}";
const MAX_REQUEST_BODY: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRoute {
    pub alias: String,
    pub secret: String,
    #[serde(default)]
    pub project: Option<String>,
    pub upstream: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub query: Vec<(String, String)>,
}

impl ProxyRoute {
    pub fn secret_ref(&self) -> SecretRef {
        SecretRef {
            project: self.project.clone(),
            name: self.secret.clone(),
        }
    }

    pub fn upstream_host(&self) -> &str {
        split_upstream(&self.upstream)
            .map(|(_, host, _)| host)
            .unwrap_or("?")
    }
}

pub struct Preset {
    pub name: &'static str,
    pub upstream: &'static str,
    pub header: (&'static str, &'static str),
    pub secret: &'static str,
    /// Path appended to the local base URL that SDKs expect (e.g. `/v1`).
    pub base_path: &'static str,
    /// SDK environment variables for base URL and key, when well known.
    pub env: Option<(&'static str, &'static str)>,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "openai",
        upstream: "https://api.openai.com",
        header: ("Authorization", "Bearer {secret}"),
        secret: "OPENAI_API_KEY",
        base_path: "/v1",
        env: Some(("OPENAI_BASE_URL", "OPENAI_API_KEY")),
    },
    Preset {
        name: "anthropic",
        upstream: "https://api.anthropic.com",
        header: ("x-api-key", "{secret}"),
        secret: "ANTHROPIC_API_KEY",
        base_path: "",
        env: Some(("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY")),
    },
    Preset {
        name: "gemini",
        upstream: "https://generativelanguage.googleapis.com",
        header: ("x-goog-api-key", "{secret}"),
        secret: "GEMINI_API_KEY",
        base_path: "",
        env: None,
    },
    Preset {
        name: "openrouter",
        upstream: "https://openrouter.ai/api",
        header: ("Authorization", "Bearer {secret}"),
        secret: "OPENROUTER_API_KEY",
        base_path: "/v1",
        env: None,
    },
    Preset {
        name: "groq",
        upstream: "https://api.groq.com/openai",
        header: ("Authorization", "Bearer {secret}"),
        secret: "GROQ_API_KEY",
        base_path: "/v1",
        env: None,
    },
    Preset {
        name: "mistral",
        upstream: "https://api.mistral.ai",
        header: ("Authorization", "Bearer {secret}"),
        secret: "MISTRAL_API_KEY",
        base_path: "/v1",
        env: None,
    },
    Preset {
        name: "github",
        upstream: "https://api.github.com",
        header: ("Authorization", "Bearer {secret}"),
        secret: "GITHUB_TOKEN",
        base_path: "",
        env: None,
    },
];

pub fn find_preset(name: &str) -> Option<&'static Preset> {
    PRESETS
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name.trim()))
}

pub fn validate_alias(alias: &str) -> Result<String, String> {
    let alias = alias.trim().to_ascii_lowercase();
    if alias.is_empty()
        || !alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "Invalid route alias '{alias}': use letters, digits, '-' or '_'"
        ));
    }
    Ok(alias)
}

/// Splits `scheme://host[:port][/base]` and enforces HTTPS (plain HTTP only to
/// loopback, for local services and tests). Userinfo, query and fragment are
/// rejected so the destination host can never be smuggled.
fn split_upstream(upstream: &str) -> Result<(&str, &str, &str), String> {
    let (scheme, rest) = upstream
        .split_once("://")
        .ok_or_else(|| format!("Upstream '{upstream}' must start with https://"))?;
    let (authority, base) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains(['@', '?', '#', ' ']) || base.contains(['?', '#'])
    {
        return Err(format!("Invalid upstream URL '{upstream}'"));
    }
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map(|(h, _)| h)
        .unwrap_or(authority);
    match scheme {
        "https" => {}
        "http" if matches!(host, "127.0.0.1" | "localhost" | "[::1]") => {}
        _ => return Err(format!("Upstream '{upstream}' must use https://")),
    }
    Ok((scheme, host, base))
}

pub fn normalize_upstream(upstream: &str) -> Result<String, String> {
    let upstream = upstream.trim().trim_end_matches('/').to_string();
    split_upstream(&upstream)?;
    Ok(upstream)
}

pub fn parse_header_template(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw.split_once(':').ok_or_else(|| {
        format!("Header '{raw}' must look like 'Name: value with {SECRET_PLACEHOLDER}'")
    })?;
    let name = name.trim();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("Invalid header name in '{raw}'"));
    }
    Ok((name.to_string(), value.trim().to_string()))
}

pub fn parse_query_template(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw.split_once('=').ok_or_else(|| {
        format!("Query parameter '{raw}' must look like 'key={SECRET_PLACEHOLDER}'")
    })?;
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("Invalid query parameter '{raw}'"));
    }
    Ok((name.to_string(), value.trim().to_string()))
}

pub fn build_route(
    alias: &str,
    secret: &str,
    project: Option<&str>,
    upstream: &str,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
) -> Result<ProxyRoute, String> {
    let route = ProxyRoute {
        alias: validate_alias(alias)?,
        secret: crate::vault::validate_secret_name(secret)?,
        project: normalize_project(project),
        upstream: normalize_upstream(upstream)?,
        headers,
        query,
    };
    let uses_secret = route
        .headers
        .iter()
        .chain(route.query.iter())
        .any(|(_, v)| v.contains(SECRET_PLACEHOLDER));
    if !uses_secret {
        return Err(format!(
            "Route '{}' never sends the secret: add --header 'Authorization: Bearer {SECRET_PLACEHOLDER}' (or --query 'key={SECRET_PLACEHOLDER}')",
            route.alias
        ));
    }
    Ok(route)
}

pub fn local_base_url(port: u16, route: &ProxyRoute) -> String {
    let suffix = PRESETS
        .iter()
        .find(|p| p.name == route.alias && route.upstream == p.upstream)
        .map(|p| p.base_path)
        .unwrap_or("");
    format!("http://127.0.0.1:{port}/{}{suffix}", route.alias)
}

/// Lines an app or agent can put in its environment to use a route.
pub fn env_lines(port: u16, route: &ProxyRoute) -> Vec<String> {
    let base = local_base_url(port, route);
    match PRESETS
        .iter()
        .find(|p| p.name == route.alias && route.upstream == p.upstream)
        .and_then(|p| p.env)
    {
        Some((base_var, key_var)) => vec![
            format!("{base_var}={base}"),
            format!("{key_var}=apiman-proxy"),
        ],
        None => vec![format!(
            "# {}: base URL {base} (any placeholder key works)",
            route.alias
        )],
    }
}

const HOP_BY_HOP: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

fn json_error(status: u16, message: &str) -> tiny_http::ResponseBox {
    let body =
        serde_json::json!({ "error": { "type": "apiman_proxy", "message": message } }).to_string();
    tiny_http::Response::from_string(body)
        .with_status_code(status)
        .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
        .boxed()
}

struct MaskingReader<R> {
    inner: R,
    masker: Masker,
    pending: Zeroizing<Vec<u8>>,
    out: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl<R: Read> Read for MaskingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.out.len() {
                let n = buf.len().min(self.out.len() - self.pos);
                buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            self.out.clear();
            self.pos = 0;
            let mut chunk = [0u8; 8192];
            let n = self.inner.read(&mut chunk)?;
            if n == 0 {
                self.eof = true;
            } else {
                self.pending.extend_from_slice(&chunk[..n]);
            }
            self.masker
                .process(&mut self.pending, &mut self.out, self.eof);
        }
    }
}

pub struct ProxyServer {
    pub vault_path: PathBuf,
    pub socket_path: PathBuf,
    pub port: u16,
    agent: ureq::Agent,
}

impl ProxyServer {
    pub fn new(vault_path: PathBuf, socket_path: PathBuf, port: u16) -> Self {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(600))
            .build();
        Self {
            vault_path,
            socket_path,
            port,
            agent,
        }
    }

    fn allowed_host(&self, host: &str) -> bool {
        let p = self.port;
        [
            format!("127.0.0.1:{p}"),
            format!("localhost:{p}"),
            format!("[::1]:{p}"),
        ]
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
    }

    fn load_vault(&self) -> Result<Vault, (u16, String)> {
        let key = get_cached_master_key(&self.socket_path).ok_or((
            423,
            "apiman vault is locked: run `apiman unlock` in a terminal".to_string(),
        ))?;
        load_vault_with_key(&key, &self.vault_path)
            .map(|(v, _)| v)
            .map_err(|e| (500, format!("apiman could not read the vault: {e}")))
    }

    pub fn handle(&self, mut request: tiny_http::Request) {
        let started = Instant::now();
        let method = request.method().as_str().to_string();
        let raw_url = request.url().to_string();
        let (path, client_query) = match raw_url.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (raw_url.clone(), None),
        };

        let header = |name: &str| {
            request
                .headers()
                .iter()
                .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
                .map(|h| h.value.as_str().to_string())
        };
        // Browsers send Origin/Sec-Fetch-*; a rebinding page sends a foreign Host.
        if header("Origin").is_some() || header("Sec-Fetch-Site").is_some() {
            let _ = request.respond(json_error(403, "browser requests are not allowed"));
            return;
        }
        if !header("Host").is_some_and(|h| self.allowed_host(&h)) {
            let _ = request.respond(json_error(403, "unexpected Host header"));
            return;
        }

        let trimmed = path.trim_start_matches('/');
        let (alias, rest) = match trimmed.split_once('/') {
            Some((a, r)) => (a.to_ascii_lowercase(), format!("/{r}")),
            None => (trimmed.to_ascii_lowercase(), String::new()),
        };

        let vault = match self.load_vault() {
            Ok(v) => v,
            Err((code, msg)) => {
                let _ = request.respond(json_error(code, &msg));
                return;
            }
        };
        let Some(route) = vault
            .proxy_routes
            .iter()
            .find(|r| r.alias == alias)
            .cloned()
        else {
            let known: Vec<&str> = vault
                .proxy_routes
                .iter()
                .map(|r| r.alias.as_str())
                .collect();
            let _ = request.respond(json_error(
                404,
                &format!(
                    "no apiman route '{alias}' (configured: {})",
                    known.join(", ")
                ),
            ));
            return;
        };
        let secret = match vault.resolve_ref(&route.secret_ref()) {
            Ok(e) => Zeroizing::new(e.value.expose_secret().to_string()),
            Err(e) => {
                let _ = request.respond(json_error(502, &format!("route '{alias}': {e}")));
                return;
            }
        };
        drop(vault);

        let mut url = format!("{}{rest}", route.upstream);
        let mut query_parts: Vec<String> =
            client_query.into_iter().filter(|q| !q.is_empty()).collect();
        for (k, v) in &route.query {
            query_parts.push(format!(
                "{}={}",
                url_encode(k),
                url_encode(&v.replace(SECRET_PLACEHOLDER, &secret))
            ));
        }
        if !query_parts.is_empty() {
            url.push('?');
            url.push_str(&query_parts.join("&"));
        }
        let url = Zeroizing::new(url);

        let mut upstream_req = self.agent.request(&method, &url);
        let injected: Vec<&str> = route.headers.iter().map(|(n, _)| n.as_str()).collect();
        for h in request.headers() {
            let name = h.field.as_str().as_str();
            let lower = name.to_ascii_lowercase();
            if HOP_BY_HOP.contains(&lower.as_str())
                || lower == "accept-encoding"
                || injected.iter().any(|i| i.eq_ignore_ascii_case(name))
            {
                continue;
            }
            upstream_req = upstream_req.set(name, h.value.as_str());
        }
        for (name, template) in &route.headers {
            let value = Zeroizing::new(template.replace(SECRET_PLACEHOLDER, &secret));
            upstream_req = upstream_req.set(name, &value);
        }

        let mut body = Vec::new();
        if let Err(e) = request
            .as_reader()
            .take(MAX_REQUEST_BODY)
            .read_to_end(&mut body)
        {
            let _ = request.respond(json_error(
                400,
                &format!("could not read request body: {e}"),
            ));
            return;
        }

        let result = if body.is_empty()
            && matches!(method.as_str(), "GET" | "HEAD" | "DELETE" | "OPTIONS")
        {
            upstream_req.call()
        } else {
            upstream_req.send_bytes(&body)
        };
        let response = match result {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(e) => {
                eprintln!(
                    "502 {method} /{alias}{rest} -> {} ({e})",
                    route.upstream_host()
                );
                let _ = request.respond(json_error(502, &format!("upstream request failed: {e}")));
                return;
            }
        };

        let status = response.status();
        let mut headers = Vec::new();
        for name in response.headers_names() {
            if HOP_BY_HOP.contains(&name.to_ascii_lowercase().as_str()) {
                continue;
            }
            for value in response.all(&name) {
                if let Ok(h) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
                    headers.push(h);
                }
            }
        }
        let reader = MaskingReader {
            inner: response.into_reader(),
            masker: Masker::new([(route.secret.as_str(), secret.as_str())]),
            pending: Zeroizing::new(Vec::new()),
            out: Vec::new(),
            pos: 0,
            eof: false,
        };
        let reply =
            tiny_http::Response::new(tiny_http::StatusCode(status), headers, reader, None, None);
        let _ = request.respond(reply);
        eprintln!(
            "{status} {method} /{alias}{rest} -> {} ({} ms)",
            route.upstream_host(),
            started.elapsed().as_millis()
        );
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn serve(server: ProxyServer, bind: &str) -> Result<(), String> {
    let listener = tiny_http::Server::http((bind, server.port))
        .map_err(|e| format!("Cannot listen on {bind}:{}: {e}", server.port))?;
    let server = Arc::new(server);
    for request in listener.incoming_requests() {
        let s = Arc::clone(&server);
        std::thread::spawn(move || s.handle(request));
    }
    Ok(())
}

pub fn is_loopback_bind(bind: &str) -> bool {
    matches!(bind, "127.0.0.1" | "localhost" | "::1")
}

pub fn vault_routes_summary(vault: &Vault, port: u16) -> Vec<String> {
    vault
        .proxy_routes
        .iter()
        .map(|r| {
            format!(
                "  {:<12} {} -> {}  (secret {})",
                r.alias,
                local_base_url(port, r),
                r.upstream,
                r.secret_ref()
            )
        })
        .collect()
}
