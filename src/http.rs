// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

use crate::errors::{IicpError, Result};

/// Generate a W3C traceparent header value (SDK-06).
/// Format: `00-<32hex>-<16hex>-01`
pub fn make_traceparent() -> String {
    let trace_id = Uuid::new_v4().simple().to_string(); // 32 hex chars
    let parent_id = &Uuid::new_v4().simple().to_string()[..16]; // 16 hex chars
    format!("00-{trace_id}-{parent_id}-01")
}

pub(crate) struct HttpClient {
    inner: Client,
    token: Option<String>,
    timeout_ms: u64,
}

impl HttpClient {
    pub(crate) fn new(timeout_ms: u64, token: Option<String>) -> Result<Self> {
        let inner = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .use_rustls_tls()
            .build()?;
        Ok(Self {
            inner,
            token,
            timeout_ms,
        })
    }

    fn auth(&self, rb: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        traceparent: Option<&str>,
    ) -> Result<T> {
        let tp = traceparent
            .map(|s| s.to_owned())
            .unwrap_or_else(make_traceparent);
        let resp = self
            .auth(self.inner.get(url))
            .header("traceparent", &tp)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body: Value = resp.json().await?;
        if status >= 400 {
            return Err(IicpError::Protocol {
                code: body["error"]["code"].as_str().unwrap_or("unknown").into(),
                message: body["error"]["message"].as_str().unwrap_or("").into(),
                status,
            });
        }
        Ok(serde_json::from_value(body)?)
    }

    /// Expose the inner `Client` for consumer token acquisition.
    pub(crate) fn inner(&self) -> &Client {
        &self.inner
    }

    /// Like `post_json` but also sends `X-IICP-Consumer-Token` when `consumer_token` is `Some`.
    pub(crate) async fn post_json_ct<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
        auth_override: Option<&str>,
        consumer_token: Option<&str>,
        traceparent: Option<&str>,
    ) -> Result<T> {
        let tp = traceparent
            .map(|s| s.to_owned())
            .unwrap_or_else(make_traceparent);
        let mut current = url.to_string();
        let mut redirects = 0usize;
        let resp = loop {
            let resolved = crate::endpoint_security::resolve_endpoint(&current).await?;
            let selected = *resolved.addresses.first().ok_or_else(|| {
                IicpError::EndpointRefused("provider hostname returned no addresses".into())
            })?;
            let pinned = Client::builder()
                .timeout(Duration::from_millis(self.timeout_ms))
                .use_rustls_tls()
                .redirect(reqwest::redirect::Policy::none())
                .resolve(&resolved.host, selected)
                .build()?;
            let mut rb = pinned
                .post(resolved.url)
                .json(body)
                .header("traceparent", &tp);
            rb = match auth_override {
                Some(t) => rb.bearer_auth(t),
                None => match &self.token {
                    Some(t) => rb.bearer_auth(t),
                    None => rb,
                },
            };
            if let Some(ct) = consumer_token {
                rb = rb.header("X-IICP-Consumer-Token", ct);
            }
            let candidate = rb.send().await?;
            if matches!(candidate.status().as_u16(), 307 | 308) {
                if redirects >= 3 {
                    return Err(IicpError::EndpointRefused(
                        "provider redirect limit exceeded".into(),
                    ));
                }
                let location = candidate
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        IicpError::EndpointRefused("provider redirect omitted Location".into())
                    })?;
                let next = candidate.url().join(location).map_err(|_| {
                    IicpError::EndpointRefused("provider redirect Location is invalid".into())
                })?;
                if next.origin() != candidate.url().origin() {
                    return Err(IicpError::EndpointRefused(
                        "cross-origin provider redirect is not allowed".into(),
                    ));
                }
                current = next.to_string();
                redirects += 1;
                continue;
            }
            if candidate.status().is_redirection() {
                return Err(IicpError::EndpointRefused(
                    "provider redirect method is not allowed".into(),
                ));
            }
            break candidate;
        };
        let status = resp.status().as_u16();
        let resp_body: Value = resp.json().await?;
        if status >= 400 {
            return Err(IicpError::Protocol {
                code: resp_body["error"]["code"]
                    .as_str()
                    .unwrap_or("unknown")
                    .into(),
                message: resp_body["error"]["message"].as_str().unwrap_or("").into(),
                status,
            });
        }
        Ok(serde_json::from_value(resp_body)?)
    }
}
