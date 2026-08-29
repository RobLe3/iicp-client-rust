// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

use crate::errors::{IicpError, Result};
use crate::http_resource::{encode_request, validate_response_headers, MAX_HTTP_TASK_BODY_BYTES};

/// Generate a W3C traceparent header value (SDK-06).
/// Format: `00-<32hex>-<16hex>-01`
pub fn make_traceparent() -> String {
    let trace_id = Uuid::new_v4().simple().to_string(); // 32 hex chars
    let parent_id = &Uuid::new_v4().simple().to_string()[..16]; // 16 hex chars
    format!("00-{trace_id}-{parent_id}-01")
}

async fn decode_task_response(mut response: reqwest::Response) -> Result<Value> {
    let status = response.status().as_u16();
    validate_response_headers(response.headers()).map_err(|error| IicpError::Protocol {
        code: error.code.into(),
        message: error.message,
        status: error.status,
    })?;
    let mut encoded = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if encoded.len() + chunk.len() > MAX_HTTP_TASK_BODY_BYTES {
            return Err(IicpError::Protocol {
                code: "response_too_large".into(),
                message: format!(
                    "encoded task response exceeds {} bytes",
                    MAX_HTTP_TASK_BODY_BYTES
                ),
                status: 500,
            });
        }
        encoded.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&encoded).map_err(|_| IicpError::Protocol {
        code: "invalid_http_body".into(),
        message: "provider returned invalid JSON".into(),
        status: if status >= 400 { status } else { 500 },
    })?;
    if status >= 400 {
        return Err(IicpError::Protocol {
            code: body["error"]["code"].as_str().unwrap_or("unknown").into(),
            message: body["error"]["message"].as_str().unwrap_or("").into(),
            status,
        });
    }
    Ok(body)
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

    /// Authenticated request to one configured restricted-directory authority.
    /// Redirects are disabled so membership evidence cannot cross an authority
    /// boundary. The caller validates the returned decision projection.
    pub(crate) async fn get_restricted_json(
        &self,
        url: &str,
        membership: &str,
        subject_id: &str,
        traceparent: Option<&str>,
    ) -> Result<Value> {
        let tp = traceparent
            .map(str::to_owned)
            .unwrap_or_else(make_traceparent);
        let client = Client::builder()
            .timeout(Duration::from_millis(self.timeout_ms))
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let resp = client
            .get(url)
            .header("traceparent", tp)
            .header("X-IICP-Membership", membership)
            .header("X-IICP-Subject-Id", subject_id)
            .send()
            .await?;
        if resp.status().is_redirection() {
            return Err(IicpError::EndpointRefused(
                "restricted directory redirect is not allowed".into(),
            ));
        }
        let status = resp.status().as_u16();
        let body: Value = resp.json().await?;
        if status >= 400 {
            return Err(IicpError::Protocol {
                code: body["error"]["code"].as_str().unwrap_or("unknown").into(),
                message: body["error"]["message"].as_str().unwrap_or("").into(),
                status,
            });
        }
        Ok(body)
    }

    pub(crate) async fn post_restricted_json<B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
        membership: &str,
        subject_id: &str,
        auth_override: Option<&str>,
        traceparent: Option<&str>,
    ) -> Result<(u16, Value)> {
        let tp = traceparent
            .map(str::to_owned)
            .unwrap_or_else(make_traceparent);
        let client = Client::builder()
            .timeout(Duration::from_millis(self.timeout_ms))
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let mut request = client
            .post(url)
            .header("traceparent", tp)
            .header("X-IICP-Membership", membership)
            .header("X-IICP-Subject-Id", subject_id)
            .json(body);
        request = match auth_override {
            Some(token) => request.bearer_auth(token),
            None => match &self.token {
                Some(token) => request.bearer_auth(token),
                None => request,
            },
        };
        let response = request.send().await?;
        if response.status().is_redirection() {
            return Err(IicpError::EndpointRefused(
                "restricted directory redirect is not allowed".into(),
            ));
        }
        let status = response.status().as_u16();
        let response_body: Value = response.json().await?;
        Ok((status, response_body))
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
        self.post_json_ct_with_policy(url, body, auth_override, consumer_token, traceparent, None)
            .await
    }

    async fn post_json_ct_with_policy<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
        auth_override: Option<&str>,
        consumer_token: Option<&str>,
        traceparent: Option<&str>,
        allow_private: Option<bool>,
    ) -> Result<T> {
        let tp = traceparent
            .map(|s| s.to_owned())
            .unwrap_or_else(make_traceparent);
        let encoded_request = encode_request(body).map_err(|error| IicpError::Protocol {
            code: error.code.into(),
            message: error.message,
            status: error.status,
        })?;
        let mut current = url.to_string();
        let mut redirects = 0usize;
        let resp = loop {
            let resolved = match allow_private {
                Some(allow) => {
                    crate::endpoint_security::resolve_endpoint_with_policy(&current, allow).await?
                }
                None => crate::endpoint_security::resolve_endpoint(&current).await?,
            };
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
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::ACCEPT, "application/json")
                .body(encoded_request.clone())
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
        let resp_body = decode_task_response(resp).await?;
        Ok(serde_json::from_value(resp_body)?)
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        response::Redirect,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::{json, Value};

    use super::*;

    #[tokio::test]
    async fn tls_handshake_failure_is_transient_and_bounded() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let client = HttpClient::new(2_000, None).unwrap();
        let error = client
            .get_json::<Value>(&format!("https://{address}/"), None)
            .await
            .unwrap_err();
        assert!(matches!(error, IicpError::Http(_)));
        assert!(error.is_transient());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn private_provider_requires_opt_in_and_uses_pinned_transport() {
        let app = Router::new()
            .route("/redirect", post(|| async { Redirect::temporary("/task") }))
            .route("/task", post(|| async { Json(json!({"ok": true})) }))
            .route("/health", get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = HttpClient::new(2_000, None).unwrap();
        let url = format!("http://{address}/redirect");

        let refused = client
            .post_json_ct_with_policy::<_, Value>(&url, &json!({}), None, None, None, Some(false))
            .await
            .unwrap_err();
        assert!(matches!(refused, IicpError::EndpointRefused(_)));

        let response: Value = client
            .post_json_ct_with_policy(&url, &json!({}), None, None, None, Some(true))
            .await
            .unwrap();
        assert_eq!(response, json!({"ok": true}));
        server.abort();
    }

    #[tokio::test]
    async fn oversize_request_is_rejected_before_endpoint_resolution() {
        let client = HttpClient::new(2_000, None).unwrap();
        let overhead = serde_json::to_vec(&json!({"padding": ""})).unwrap().len();
        let body = json!({"padding": "x".repeat(MAX_HTTP_TASK_BODY_BYTES + 1 - overhead)});
        let error = client
            .post_json_ct_with_policy::<_, Value>(
                "not-a-provider-url",
                &body,
                None,
                None,
                None,
                Some(true),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            IicpError::Protocol { ref code, status: 413, .. } if code == "request_too_large"
        ));
        assert!(!error.is_transient());
    }

    #[tokio::test]
    async fn declared_oversize_response_is_aborted_and_non_transient() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        MAX_HTTP_TASK_BODY_BYTES + 1
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let client = HttpClient::new(2_000, None).unwrap();
        let error = client
            .post_json_ct_with_policy::<_, Value>(
                &format!("http://{address}/task"),
                &json!({}),
                None,
                None,
                None,
                Some(true),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            IicpError::Protocol { ref code, status: 500, .. } if code == "response_too_large"
        ));
        assert!(!error.is_transient());
        server.abort();
    }
}
