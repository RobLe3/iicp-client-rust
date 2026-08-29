// SPDX-License-Identifier: Apache-2.0
//! Finite resource boundary for the supported HTTP `POST /v1/task` binding.

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap};
use serde::Serialize;

pub(crate) const MAX_HTTP_TASK_BODY_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpResourceError {
    pub(crate) status: u16,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl HttpResourceError {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

fn split_header_values(
    headers: &HeaderMap,
    name: header::HeaderName,
) -> Result<Vec<String>, HttpResourceError> {
    let mut values = Vec::new();
    for value in headers.get_all(name) {
        let value = value
            .to_str()
            .map_err(|_| HttpResourceError::new(400, "invalid_http_body", "invalid HTTP header"))?;
        values.extend(value.split(',').map(str::trim).map(str::to_owned));
    }
    Ok(values)
}

pub(crate) fn validate_identity_encoding(headers: &HeaderMap) -> Result<(), HttpResourceError> {
    let encodings = split_header_values(headers, header::CONTENT_ENCODING)?;
    if encodings
        .iter()
        .any(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err(HttpResourceError::new(
            415,
            "unsupported_content_encoding",
            "supported HTTP task binding accepts identity encoding only",
        ));
    }
    Ok(())
}

pub(crate) fn content_length(headers: &HeaderMap) -> Result<Option<usize>, HttpResourceError> {
    let values = split_header_values(headers, header::CONTENT_LENGTH)?;
    if values.is_empty() {
        return Ok(None);
    }
    let parsed: Vec<usize> = values
        .iter()
        .map(|value| parse_content_length_value(value))
        .collect::<Result<_, _>>()?;
    require_matching_content_lengths(&parsed)?;
    Ok(parsed.first().copied())
}

fn parse_content_length_value(value: &str) -> Result<usize, HttpResourceError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_content_length("invalid Content-Length"));
    }
    value
        .parse::<usize>()
        .map_err(|_| invalid_content_length("invalid Content-Length"))
}

fn require_matching_content_lengths(values: &[usize]) -> Result<(), HttpResourceError> {
    if values.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(HttpResourceError::new(
            400,
            "invalid_http_body",
            "conflicting Content-Length",
        ));
    }
    Ok(())
}

fn invalid_content_length(message: &'static str) -> HttpResourceError {
    HttpResourceError::new(400, "invalid_http_body", message)
}

pub(crate) fn validate_request_headers(headers: &HeaderMap) -> Result<(), HttpResourceError> {
    validate_identity_encoding(headers)?;
    let length = content_length(headers)?;
    if headers.contains_key(header::TRANSFER_ENCODING) && length.is_some() {
        return Err(HttpResourceError::new(
            400,
            "invalid_http_body",
            "Content-Length and Transfer-Encoding cannot be combined",
        ));
    }
    if length.is_some_and(|value| value > MAX_HTTP_TASK_BODY_BYTES) {
        return Err(HttpResourceError::new(
            413,
            "request_too_large",
            format!(
                "encoded task request exceeds {} bytes",
                MAX_HTTP_TASK_BODY_BYTES
            ),
        ));
    }
    Ok(())
}

pub(crate) fn validate_response_headers(headers: &HeaderMap) -> Result<(), HttpResourceError> {
    validate_identity_encoding(headers)?;
    if content_length(headers)?.is_some_and(|value| value > MAX_HTTP_TASK_BODY_BYTES) {
        return Err(HttpResourceError::new(
            500,
            "response_too_large",
            format!(
                "encoded task response exceeds {} bytes",
                MAX_HTTP_TASK_BODY_BYTES
            ),
        ));
    }
    Ok(())
}

pub(crate) fn encode_request<T: Serialize>(value: &T) -> Result<Vec<u8>, HttpResourceError> {
    let body = serde_json::to_vec(value).map_err(|_| {
        HttpResourceError::new(400, "invalid_http_body", "task request is not valid JSON")
    })?;
    if body.len() > MAX_HTTP_TASK_BODY_BYTES {
        return Err(HttpResourceError::new(
            413,
            "request_too_large",
            format!(
                "encoded task request exceeds {} bytes",
                MAX_HTTP_TASK_BODY_BYTES
            ),
        ));
    }
    Ok(body)
}

pub(crate) async fn read_request_body(
    headers: &HeaderMap,
    body: Body,
) -> Result<Vec<u8>, HttpResourceError> {
    validate_request_headers(headers)?;
    to_bytes(body, MAX_HTTP_TASK_BODY_BYTES)
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|_| {
            HttpResourceError::new(
                413,
                "request_too_large",
                format!(
                    "encoded task request exceeds {} bytes",
                    MAX_HTTP_TASK_BODY_BYTES
                ),
            )
        })
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use serde_json::json;

    use super::*;

    fn json_value_with_size(size: usize) -> serde_json::Value {
        let overhead = serde_json::to_vec(&json!({"padding": ""})).unwrap().len();
        let value = json!({"padding": "x".repeat(size - overhead)});
        assert_eq!(serde_json::to_vec(&value).unwrap().len(), size);
        value
    }

    #[test]
    fn exact_request_limit_passes_and_limit_plus_one_fails() {
        assert_eq!(
            encode_request(&json_value_with_size(MAX_HTTP_TASK_BODY_BYTES))
                .unwrap()
                .len(),
            MAX_HTTP_TASK_BODY_BYTES
        );
        let error =
            encode_request(&json_value_with_size(MAX_HTTP_TASK_BODY_BYTES + 1)).unwrap_err();
        assert_eq!((error.status, error.code), (413, "request_too_large"));
    }

    #[test]
    fn shared_fixture_matches_implementation_boundary() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../parity/http-task-resource-boundary-v1.json"
        ))
        .unwrap();
        assert_eq!(
            fixture["max_encoded_request_bytes"].as_u64(),
            Some(MAX_HTTP_TASK_BODY_BYTES as u64)
        );
        assert_eq!(
            fixture["max_encoded_response_bytes"].as_u64(),
            Some(MAX_HTTP_TASK_BODY_BYTES as u64)
        );
        assert_eq!(fixture["supported_content_encodings"], json!(["identity"]));
    }

    #[test]
    fn conflicting_lengths_and_encoding_fail_closed() {
        let mut headers = HeaderMap::new();
        headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("12"));
        headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("13"));
        assert_eq!(
            content_length(&headers).unwrap_err().code,
            "invalid_http_body"
        );
        headers.clear();
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(
            validate_identity_encoding(&headers).unwrap_err().code,
            "unsupported_content_encoding"
        );
    }

    #[tokio::test]
    async fn chunked_or_lengthless_body_is_bounded_incrementally() {
        let headers = HeaderMap::new();
        let exact = vec![b'x'; MAX_HTTP_TASK_BODY_BYTES];
        assert_eq!(
            read_request_body(&headers, Body::from(exact))
                .await
                .unwrap()
                .len(),
            MAX_HTTP_TASK_BODY_BYTES
        );
        let error = read_request_body(
            &headers,
            Body::from(vec![b'x'; MAX_HTTP_TASK_BODY_BYTES + 1]),
        )
        .await
        .unwrap_err();
        assert_eq!((error.status, error.code), (413, "request_too_large"));
    }
}
