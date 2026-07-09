// SPDX-License-Identifier: Apache-2.0
//! Client-side policy guardrails.
//!
//! This is intentionally narrow: it refuses intent URNs aligned with EU AI Act
//! prohibited-practice families before discovery, without turning the SDK into a
//! broad legal compliance engine.

use crate::errors::{IicpError, Result};

pub const POLICY_REFUSAL_CODE: &str = "IICP-POLICY-001";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentRiskCategory {
    Prohibited,
    HighRisk,
    TransparencyRisk,
    MinimalOrGeneral,
}

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

pub const HIGH_RISK_INTENT_RULES: &[ProhibitedIntentRule] = &[
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-employment-workforce",
        label: "employment or workforce decision",
        fragments: &[
            "employment:hiring",
            "employment:screen",
            "employment:rank",
            "recruitment:decision",
            "workforce:decision",
            "worker-management",
            "worker:performance",
            "worker:discipline",
        ],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-education-admission-grading",
        label: "education admission or grading decision",
        fragments: &[
            "education:admission",
            "education:grading",
            "education:grade",
            "student:admission",
            "student:assess",
            "exam-grading",
        ],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-credit-essential-services",
        label: "credit or essential-services decision",
        fragments: &[
            "credit-scoring",
            "credit:score",
            "credit:decision",
            "essential-services",
            "benefits:eligibility",
            "public-benefit:eligibility",
        ],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-law-enforcement-border-justice",
        label: "law enforcement, border, justice or democratic-process decision",
        fragments: &[
            "law-enforcement",
            "law_enforcement",
            "migration:decision",
            "asylum:decision",
            "border-control",
            "justice:decision",
            "democratic-process",
            "election:decision",
        ],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-healthcare-critical-infrastructure",
        label: "healthcare or critical-infrastructure safety decision",
        fragments: &[
            "healthcare:decision",
            "medical:diagnosis",
            "medical:triage",
            "clinical:decision",
            "critical-infrastructure",
            "grid:stabilize",
            "hospital:surge-capacity",
        ],
    },
    ProhibitedIntentRule {
        rule_id: "eu-ai-act-physical-world-control",
        label: "physical-world control",
        fragments: &[
            "robotics:control",
            "robotics:fleet",
            "drone:control",
            "drone:search",
            "iot:actuate",
            "physical-world",
            "system_control",
        ],
    },
];

const TRANSPARENCY_FRAGMENTS: &[&str] = &[
    "chatbot",
    "ai-assistant",
    "synthetic-media",
    "deepfake:labelled",
    "content:generate-public",
    "creative:generate",
];

pub fn classify_intent(intent: &str) -> IntentRiskCategory {
    let normalized = intent.trim().to_ascii_lowercase();
    if PROHIBITED_INTENT_RULES
        .iter()
        .any(|r| r.fragments.iter().any(|f| normalized.contains(f)))
    {
        return IntentRiskCategory::Prohibited;
    }
    if HIGH_RISK_INTENT_RULES
        .iter()
        .any(|r| r.fragments.iter().any(|f| normalized.contains(f)))
    {
        return IntentRiskCategory::HighRisk;
    }
    if TRANSPARENCY_FRAGMENTS
        .iter()
        .any(|f| normalized.contains(f))
    {
        return IntentRiskCategory::TransparencyRisk;
    }
    IntentRiskCategory::MinimalOrGeneral
}

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
    let category = classify_intent(intent);
    let normalized = intent.trim().to_ascii_lowercase();
    let rule = PROHIBITED_INTENT_RULES
        .iter()
        .chain(HIGH_RISK_INTENT_RULES.iter())
        .find(|r| r.fragments.iter().any(|f| normalized.contains(f)));
    if matches!(
        category,
        IntentRiskCategory::Prohibited | IntentRiskCategory::HighRisk
    ) {
        let reason = rule
            .map(|r| format!("{} ({})", r.label, r.rule_id))
            .unwrap_or_else(|| "restricted intent".into());
        return Err(IicpError::PolicyRefused {
            code: POLICY_REFUSAL_CODE.into(),
            message: format!(
                "Intent refused by IICP client policy before discovery/routing: {reason} [{category:?}]. Use an explicit private, documented, human-reviewed compliance path outside the public mesh for restricted/high-risk workflows."
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
