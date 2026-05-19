// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::errors::{IicpError, Result};

pub(crate) struct HttpClient {
    inner: Client,
    timeout: Duration,
    token: Option<String>,
}

impl HttpClient {
    pub(crate) fn new(timeout_ms: u64, token: Option<String>) -> Result<Self> {
        let inner = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .use_rustls_tls()
            .build()?;
        Ok(Self { inner, timeout: Duration::from_millis(timeout_ms), token })
    }

    fn auth(&self, rb: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let resp = self.auth(self.inner.get(url)).send().await?;
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

    pub(crate) async fn post_json<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
        auth_override: Option<&str>,
    ) -> Result<T> {
        let rb = self.inner.post(url).json(body);
        let rb = match auth_override {
            Some(t) => rb.bearer_auth(t),
            None => self.auth(rb),
        };
        let resp = rb.send().await?;
        let status = resp.status().as_u16();
        let resp_body: Value = resp.json().await?;
        if status >= 400 {
            return Err(IicpError::Protocol {
                code: resp_body["error"]["code"].as_str().unwrap_or("unknown").into(),
                message: resp_body["error"]["message"].as_str().unwrap_or("").into(),
                status,
            });
        }
        Ok(serde_json::from_value(resp_body)?)
    }
}
