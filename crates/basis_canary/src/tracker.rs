//! HTTP client for the tracker API.
//!
//! Every request carries the API key from `--api-key-file` as `X-API-Key` (marked sensitive).
//! Responses are read with the tracker's own 2 MiB body cap. Error messages name the method and
//! the URL, which never holds credentials ([`check_url`]), and never the key.

use std::time::Duration;

use basis_store::reqwest::{self, Url};
use serde_json::Value;

use crate::keys::ApiKey;

/// Connect timeout for tracker requests.
pub const TRACKER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Total timeout of one tracker request. `POST /redemption/build` makes a dozen node requests of
/// its own (15 s timeout each), so this is well above the node client's.
pub const TRACKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Refuse a URL that is not `http(s)://` or that holds credentials (`user:password@`), so no
/// URL in a report or an error message can carry a secret.
pub fn check_url(flag: &str, url: &str) -> Result<(), String> {
    let shown = basis_store::redact::url_without_credentials(url);
    let parsed = Url::parse(url).map_err(|e| format!("{flag} {shown:?} is not a URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!(
            "{flag} {shown:?} must be an http:// or https:// URL"
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "{flag} {shown:?} holds credentials; pass the tracker key with --api-key-file"
        ));
    }
    Ok(())
}

/// One tracker answer: the HTTP status and the body.
#[derive(Debug, Clone)]
pub struct TrackerResponse {
    pub status: u16,
    pub body: String,
}

impl TrackerResponse {
    /// The body as JSON, when it is JSON.
    pub fn json(&self) -> Option<Value> {
        serde_json::from_str(&self.body).ok()
    }

    /// The body pretty-printed when it is JSON, else as received.
    pub fn pretty(&self) -> String {
        self.json()
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or_else(|| self.body.clone())
    }

    /// The tracker's `error` message, or the body when there is none.
    pub fn error_message(&self) -> String {
        match self.json() {
            Some(v) => match v.get("error").and_then(Value::as_str) {
                Some(e) => e.to_string(),
                None => v.to_string(),
            },
            None => self.body.trim().to_string(),
        }
    }

    /// `data` of a successful answer with status `expected`; an error naming `what` otherwise.
    pub fn data(&self, what: &str, expected: u16) -> Result<Value, String> {
        if self.status != expected {
            return Err(format!(
                "{what}: HTTP {}: {}",
                self.status,
                self.error_message()
            ));
        }
        let v = self
            .json()
            .ok_or_else(|| format!("{what}: the answer is not JSON: {}", self.body))?;
        if v.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(format!("{what}: the tracker reports failure: {v}"));
        }
        Ok(v.get("data").cloned().unwrap_or(Value::Null))
    }
}

/// The tracker API at one base URL.
pub struct TrackerClient {
    url: String,
    api_key: Option<ApiKey>,
    client: reqwest::Client,
}

impl std::fmt::Debug for TrackerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackerClient")
            .field("url", &basis_store::redact::Url(&self.url))
            .field("api_key", &basis_store::redact::Secret(&self.api_key))
            .finish()
    }
}

impl TrackerClient {
    /// A client for the tracker at `url` (a trailing `/` is ignored).
    pub fn new(url: &str, api_key: Option<ApiKey>) -> Result<Self, String> {
        check_url("--tracker-url", url)?;
        let client = reqwest::Client::builder()
            .connect_timeout(TRACKER_CONNECT_TIMEOUT)
            .timeout(TRACKER_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| format!("HTTP client: {e}"))?;
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            api_key,
            client,
        })
    }

    /// Base URL without a trailing `/`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether requests carry an API key.
    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    /// `GET {url}{path}`.
    pub async fn get(&self, path: &str) -> Result<TrackerResponse, String> {
        let url = format!("{}{}", self.url, path);
        self.send("GET", &url, self.client.get(&url)).await
    }

    /// `POST {url}{path}` with a JSON body.
    pub async fn post(&self, path: &str, body: &Value) -> Result<TrackerResponse, String> {
        let url = format!("{}{}", self.url, path);
        self.send("POST", &url, self.client.post(&url).json(body))
            .await
    }

    async fn send(
        &self,
        method: &str,
        url: &str,
        mut request: reqwest::RequestBuilder,
    ) -> Result<TrackerResponse, String> {
        if let Some(key) = &self.api_key {
            request = request.header("X-API-Key", key.header_value()?);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("{method} {url}: {e}"))?;
        let status = response.status().as_u16();
        let body = basis_store::http::read_body_capped(response)
            .await
            .map_err(|e| format!("{method} {url}: {e}"))?;
        if status == 401 && self.api_key.is_none() {
            return Err(format!(
                "{method} {url}: HTTP 401: the tracker wants an API key; pass --api-key-file"
            ));
        }
        Ok(TrackerResponse { status, body })
    }
}
