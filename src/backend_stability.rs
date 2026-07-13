// SPDX-License-Identifier: Apache-2.0
//! Provider-local backend stability observer and drain guard (#553).
//!
//! Conservative by design: read-only probes only, coarse public output, no
//! automatic model load/unload orchestration and no host-safety guarantee.

use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendStabilityObservation {
    pub backend_state: String,
    pub reason_class: String,
    pub drain_until_s: Option<i64>,
    pub observed_at_s: i64,
    pub diagnostics: Value,
}

impl Default for BackendStabilityObservation {
    fn default() -> Self {
        Self::ok()
    }
}

impl BackendStabilityObservation {
    pub fn ok() -> Self {
        Self {
            backend_state: "ok".into(),
            reason_class: "ok".into(),
            drain_until_s: None,
            observed_at_s: now_s(),
            diagnostics: json!({}),
        }
    }

    pub fn degraded(reason: &str) -> Self {
        Self {
            backend_state: "degraded".into(),
            reason_class: reason.into(),
            drain_until_s: None,
            observed_at_s: now_s(),
            diagnostics: json!({}),
        }
    }

    pub fn draining(reason: &str, drain_until_s: i64, diagnostics: Value) -> Self {
        Self {
            backend_state: "draining".into(),
            reason_class: reason.into(),
            drain_until_s: Some(drain_until_s),
            observed_at_s: now_s(),
            diagnostics,
        }
    }

    pub fn retry_after_s_at(&self, now: i64) -> Option<i64> {
        let remaining = self.drain_until_s? - now;
        if remaining <= 0 {
            None
        } else {
            Some(remaining.max(1))
        }
    }

    pub fn retry_after_s(&self) -> Option<i64> {
        self.retry_after_s_at(now_s())
    }

    pub fn is_draining(&self) -> bool {
        self.backend_state == "draining" && self.retry_after_s().is_some()
    }

    pub fn public_json(&self) -> Value {
        let mut out = json!({
            "backend_state": self.backend_state,
            "reason_class": self.reason_class,
        });
        if let Some(retry) = self.retry_after_s() {
            out["retry_after_s"] = json!(retry);
            out["drain_until"] = json!(self.drain_until_s.unwrap_or_default());
        }
        out
    }
}

fn now_s() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn norm(v: &Value) -> String {
    v.as_str()
        .unwrap_or("")
        .trim()
        .to_lowercase()
        .replace('-', "_")
}

fn model_matches(candidate: &str, expected_model: Option<&str>) -> bool {
    match expected_model {
        None => true,
        Some(expected) => {
            candidate == expected
                || candidate.split(':').next().unwrap_or(candidate)
                    == expected.split(':').next().unwrap_or(expected)
        }
    }
}

/// MeshLLM's OpenAI model inventory is authoritative for its currently
/// routable local/mesh-backed models. Its internal topology stays opaque.
pub fn parse_meshllm_models(data: &Value, expected_model: Option<&str>) -> BackendStabilityObservation {
    let Some(models) = data.get("data").and_then(Value::as_array) else {
        return BackendStabilityObservation::draining(
            "backend_loading", now_s() + 30, json!({"ready": false}),
        );
    };
    let present = models
        .iter()
        .filter_map(|model| model.get("id").and_then(Value::as_str))
        .any(|id| model_matches(id, expected_model));
    if expected_model.is_some() && !present {
        return BackendStabilityObservation::draining(
            "backend_loading", now_s() + 30, json!({"selected_model_ready": false}),
        );
    }
    BackendStabilityObservation::ok()
}

pub fn parse_ollama_ps(data: &Value, expected_model: Option<&str>) -> BackendStabilityObservation {
    let Some(models) = data.get("models").and_then(Value::as_array) else {
        return BackendStabilityObservation::degraded("observer_error");
    };
    let names: Vec<&str> = models
        .iter()
        .filter_map(|m| m.get("name").and_then(Value::as_str))
        .collect();
    let loaded_expected = names.iter().any(|n| model_matches(n, expected_model));
    if expected_model.is_some() && !loaded_expected {
        let mut obs = BackendStabilityObservation::degraded("backend_cold");
        obs.diagnostics =
            json!({"loaded_model_count": names.len(), "expected_model_loaded": false});
        return obs;
    }
    let mut obs = BackendStabilityObservation::ok();
    obs.diagnostics = json!({"loaded_model_count": names.len()});
    obs
}

pub fn parse_lmstudio_models(
    data: &Value,
    expected_model: Option<&str>,
    now_s: i64,
    loading_retry_s: i64,
    unstable_retry_s: i64,
) -> BackendStabilityObservation {
    let models = data
        .get("data")
        .or_else(|| data.get("models"))
        .and_then(Value::as_array);
    let Some(models) = models else {
        return BackendStabilityObservation::degraded("observer_error");
    };
    let mut saw_expected = expected_model.is_none();
    let mut saw_loaded_expected = false;
    let mut saw_loading = false;
    let mut saw_unstable = false;
    let mut loaded_count = 0usize;
    for item in models {
        let model_id = item
            .get("id")
            .or_else(|| item.get("model_key"))
            .or_else(|| item.get("path"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let expected = model_matches(model_id, expected_model);
        saw_expected |= expected;
        let instances = item
            .get("loaded_instances")
            .or_else(|| item.get("loadedInstances"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for inst in instances {
            loaded_count += 1;
            if expected {
                saw_loaded_expected = true;
            }
            let state = norm(
                inst.get("state")
                    .or_else(|| inst.get("status"))
                    .or_else(|| inst.get("load_status"))
                    .unwrap_or(&Value::Null),
            );
            if [
                "loading",
                "initializing",
                "starting",
                "warming",
                "warming_up",
            ]
            .contains(&state.as_str())
            {
                saw_loading = true;
            }
            if [
                "error",
                "failed",
                "crashed",
                "unhealthy",
                "oom",
                "out_of_memory",
            ]
            .contains(&state.as_str())
            {
                saw_unstable = true;
            }
        }
    }
    if saw_unstable {
        return BackendStabilityObservation::draining(
            "backend_unstable",
            now_s + unstable_retry_s,
            json!({"loaded_instance_count": loaded_count}),
        );
    }
    if saw_loading {
        return BackendStabilityObservation::draining(
            "backend_loading",
            now_s + loading_retry_s,
            json!({"loaded_instance_count": loaded_count}),
        );
    }
    if expected_model.is_some() && (!saw_expected || !saw_loaded_expected) {
        let mut obs = BackendStabilityObservation::degraded("backend_cold");
        obs.diagnostics =
            json!({"loaded_instance_count": loaded_count, "expected_model_loaded": false});
        return obs;
    }
    let mut obs = BackendStabilityObservation::ok();
    obs.diagnostics = json!({"loaded_instance_count": loaded_count});
    obs
}

pub async fn observe_backend_stability(
    http: &reqwest::Client,
    backend_url: &str,
    backend: Option<&str>,
    expected_model: Option<&str>,
    api_key: Option<&str>,
) -> BackendStabilityObservation {
    let base = backend_url.trim_end_matches('/');
    if base.is_empty() {
        return BackendStabilityObservation::degraded("observer_error");
    }
    let root = base.strip_suffix("/v1").unwrap_or(base);
    let flavor = backend
        .unwrap_or("")
        .trim()
        .to_lowercase()
        .replace('-', "_");
    let add_auth = |rb: reqwest::RequestBuilder| {
        if let Some(key) = api_key.filter(|k| !k.is_empty()) {
            rb.bearer_auth(key)
        } else {
            rb
        }
    };
    if flavor == "meshllm" {
        match add_auth(http.get(format!("{root}/readyz")).timeout(std::time::Duration::from_secs(2))).send().await {
            Ok(resp) if resp.status().is_success() => {}
            _ => return BackendStabilityObservation::draining(
                "backend_loading", now_s() + 30, json!({"ready": false}),
            ),
        }
        return match add_auth(http.get(format!("{root}/v1/models")).timeout(std::time::Duration::from_secs(2))).send().await {
            Ok(resp) if resp.status().is_success() => resp.json::<Value>().await
                .map(|value| parse_meshllm_models(&value, expected_model))
                .unwrap_or_else(|_| BackendStabilityObservation::draining("backend_loading", now_s() + 30, json!({"ready": false}))),
            _ => BackendStabilityObservation::draining("backend_loading", now_s() + 30, json!({"ready": false})),
        };
    }
    if flavor == "ollama" || flavor.is_empty() {
        match add_auth(
            http.get(format!("{root}/api/ps"))
                .timeout(std::time::Duration::from_secs(2)),
        )
        .send()
        .await
        {
            Ok(resp) if resp.status().is_success() => {
                return resp
                    .json::<Value>()
                    .await
                    .map(|v| parse_ollama_ps(&v, expected_model))
                    .unwrap_or_else(|_| BackendStabilityObservation::degraded("observer_error"));
            }
            _ if flavor == "ollama" => {
                return BackendStabilityObservation::degraded("observer_error")
            }
            _ => {}
        }
    }
    if matches!(
        flavor.as_str(),
        "" | "lmstudio" | "lm_studio" | "lm_studio_server"
    ) {
        match add_auth(
            http.get(format!("{root}/api/v1/models"))
                .timeout(std::time::Duration::from_secs(2)),
        )
        .send()
        .await
        {
            Ok(resp) if resp.status().is_success() => {
                return resp
                    .json::<Value>()
                    .await
                    .map(|v| parse_lmstudio_models(&v, expected_model, now_s(), 30, 60))
                    .unwrap_or_else(|_| BackendStabilityObservation::degraded("observer_error"));
            }
            _ if !flavor.is_empty() => {
                return BackendStabilityObservation::degraded("observer_error")
            }
            _ => {}
        }
    }
    BackendStabilityObservation::ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ollama_loaded_is_ok_and_redacted() {
        let obs = parse_ollama_ps(
            &json!({"models":[{"name":"qwen","size_vram":123}]}),
            Some("qwen"),
        );
        assert_eq!(obs.backend_state, "ok");
        assert_eq!(
            obs.public_json(),
            json!({"backend_state":"ok","reason_class":"ok"})
        );
    }

    #[test]
    fn meshllm_requires_the_selected_model_in_its_ready_inventory() {
        let ready = parse_meshllm_models(&json!({"data":[{"id":"stable-model"}]}), Some("stable-model"));
        assert_eq!(ready.backend_state, "ok");
        let missing = parse_meshllm_models(&json!({"data":[{"id":"other-model"}]}), Some("stable-model"));
        assert_eq!(missing.backend_state, "draining");
        assert_eq!(missing.reason_class, "backend_loading");
    }

    #[test]
    fn ollama_missing_expected_is_cold_not_draining() {
        let obs = parse_ollama_ps(&json!({"models":[]}), Some("qwen"));
        assert_eq!(obs.backend_state, "degraded");
        assert_eq!(obs.reason_class, "backend_cold");
        assert!(!obs.is_draining());
    }

    #[test]
    fn lmstudio_loading_drains_temporarily() {
        let obs = parse_lmstudio_models(
            &json!({"data":[{"id":"qwen","loaded_instances":[{"state":"loading","model_size_bytes":99}]}]}),
            Some("qwen"),
            1000,
            17,
            60,
        );
        assert_eq!(obs.backend_state, "draining");
        assert_eq!(obs.reason_class, "backend_loading");
        assert_eq!(obs.retry_after_s_at(1000), Some(17));
        let public = obs.public_json();
        assert_eq!(public["backend_state"], "draining");
        assert_eq!(public["reason_class"], "backend_loading");
        assert!(public.get("model_size_bytes").is_none());
    }
}
