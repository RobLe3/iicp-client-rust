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
}

impl HttpClient {
    pub(crate) fn new(timeout_ms: u64, token: Option<String>) -> Result<Self> {
        let inner = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .use_rustls_tls()
            .build()?;
        Ok(Self { inner, token })
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

    pub(crate) async fn post_json<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
        auth_override: Option<&str>,
        traceparent: Option<&str>,
    ) -> Result<T> {
        self.post_json_ct(url, body, auth_override, None, traceparent)
            .await
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
        let rb = self.inner.post(url).json(body).header("traceparent", &tp);
        let rb = match auth_override {
            Some(t) => rb.bearer_auth(t),
            None => self.auth(rb),
        };
        let rb = match consumer_token {
            Some(ct) => rb.header("X-IICP-Consumer-Token", ct),
            None => rb,
        };
        let resp = rb.send().await?;
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
