// SPDX-License-Identifier: Apache-2.0
//! Client-side policy guardrails.
//!
//! This is intentionally narrow: it refuses intent URNs aligned with EU AI Act
//! prohibited-practice families before discovery, without turning the SDK into a
//! broad legal compliance engine.

use crate::errors::{IicpError, Result};

pub const POLICY_REFUSAL_CODE: &str = "IICP-POLICY-001";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProhibitedIntentRule {
    pub rule_id: &'static str,
    pub label: &'static str,
    pub fragments: &'static [&'static str],
}

pub const PROHIBITED_INTENT_RULES: &[ProhibitedIntentRule] = &[
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-social-scoring",
        label: "social scoring",
        fragments: &["social-scoring", "social_scoring", "social:scoring"],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-criminal-risk",
        label: "individual criminal risk prediction",
        fragments: &[
            "criminal-risk",
            "criminal_risk",
            "criminal:risk",
            "predict-crime",
        ],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-workplace-education-emotion",
        label: "workplace or education emotion recognition",
        fragments: &[
            "emotion:workplace",
            "emotion:education",
            "workplace-monitoring",
            "education-monitoring",
            "worker-monitoring",
        ],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-protected-trait-biometric",
        label: "biometric protected-trait classification",
        fragments: &["protected-trait", "protected_trait", "biometric:protected"],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-untargeted-face-scraping",
        label: "untargeted facial image scraping for recognition databases",
        fragments: &[
            "untargeted-scraping",
            "untargeted_scraping",
            "face-scraping",
            "facial-scraping",
        ],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-realtime-remote-biometric-id",
        label: "real-time remote biometric identification",
        fragments: &[
            "remote-biometric:realtime",
            "realtime-remote-biometric",
            "real-time-remote-biometric",
        ],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-nonconsensual-sexual-deepfake",
        label: "non-consensual sexual deepfake or CSAM generation",
        fragments: &[
            "nonconsensual-sexual",
            "non-consensual-sexual",
            "child-sexual-abuse",
            "csam",
        ],
    },
];

pub fn prohibited_intent_reason(intent: &str) -> Option<String> {
    let normalized = intent.trim().to_ascii_lowercase();
    for rule in PROHIBITED_INTENT_RULES {
        if rule
            .fragments
            .iter()
            .any(|fragment| normalized.contains(fragment))
        {
            return Some(format!("{} ({})", rule.label, rule.rule_id));
        }
    }
    None
}

pub fn ensure_intent_allowed(intent: &str) -> Result<()> {
    if let Some(reason) = prohibited_intent_reason(intent) {
        return Err(IicpError::PolicyRefused {
            code: POLICY_REFUSAL_CODE.into(),
            message: format!(
                "Intent refused by IICP client policy before discovery/routing: {reason}. Use a lawful, documented, human-reviewed compliance path outside the public mesh for restricted/high-risk workflows."
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_prohibited_intent() {
        let err = ensure_intent_allowed("urn:iicp:intent:social-scoring:score:v1").unwrap_err();
        assert!(matches!(err, IicpError::PolicyRefused { .. }));
    }

    #[test]
    fn allows_normal_chat_intent() {
        ensure_intent_allowed("urn:iicp:intent:llm:chat:v1").unwrap();
    }
}
