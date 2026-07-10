// SPDX-License-Identifier: Apache-2.0
//! Fail-closed MCP tool-risk policy shared by the built-in gateway (#601).

use serde_json::{json, Value};

const RISK_KEYWORDS: &[(&str, &[&str])] = &[
    ("shell_exec", &["bash", "shell", "exec", "run_command", "command", "eval", "python_exec"]),
    ("data_read", &["read_document", "query_database", "list_resource", "dataset_read", "record_lookup"]),
    ("file_read", &["read_file", "list_dir", "cat", "open_file", "file_read", "list_files"]),
    ("file_write", &["write_file", "delete_file", "remove_file", "edit_file", "save_file", "mkdir", "rmdir"]),
    ("network_fetch", &["fetch", "crawl", "http", "web_request", "search_web", "url"]),
    ("browser_control", &["browser", "computer_use", "click", "type", "screenshot", "navigate"]),
    ("credential_access", &["secret", "credential", "token", "ssh_key", "wallet", "password"]),
    ("system_control", &["systemctl", "launchctl", "service_restart", "install_package", "firewall", "reboot", "shutdown"]),
    ("physical_world", &["robot", "drone", "actuator", "iot_control", "medical_device", "industrial_control"]),
    ("regulated_decision", &["credit_score", "hire", "employment", "benefit_eligibility", "diagnose", "triage_patient"]),
];

pub fn tool_risk_label(tool_name: &str) -> &'static str {
    let safe: String = tool_name.to_lowercase().chars()
        .map(|c| if c.is_ascii_alphanumeric() || "_:-".contains(c) { c } else { '_' })
        .collect();
    for (label, needles) in RISK_KEYWORDS {
        if needles.iter().any(|needle| safe == *needle || safe.contains(needle)) {
            return label;
        }
    }
    "benign_read"
}

#[derive(Clone, Debug, Default)]
pub struct McpToolPolicy {
    pub allow_dangerous_tools: bool,
    pub authz_policy: String,
    pub sandbox_profile: String,
    pub audit_redaction: bool,
}

impl McpToolPolicy {
    pub fn dangerous_ready(&self) -> bool {
        self.allow_dangerous_tools
            && !self.authz_policy.trim().is_empty()
            && matches!(self.sandbox_profile.trim().to_lowercase().as_str(), "1" | "true" | "strict" | "container" | "sandbox")
            && self.audit_redaction
    }

    pub fn allows(&self, tool_name: &str) -> bool {
        tool_risk_label(tool_name) == "benign_read" || self.dangerous_ready()
    }

    pub fn receipt(&self, tool_name: &str, decision: &str, argument_count: usize) -> Value {
        let safe_name: String = tool_name.chars()
            .map(|c| if c.is_ascii_alphanumeric() || "_:-".contains(c) { c } else { '_' })
            .take(96).collect();
        json!({
            "tool_name": safe_name,
            "tool_risk": tool_risk_label(tool_name),
            "decision": decision,
            "authz_policy": if self.authz_policy.is_empty() { Value::Null } else { json!(self.authz_policy.chars().take(96).collect::<String>()) },
            "sandbox_profile": if self.sandbox_profile.is_empty() { Value::Null } else { json!(self.sandbox_profile.chars().take(32).collect::<String>()) },
            "audit_redacted": self.audit_redaction,
            "argument_count": argument_count,
            "argument_content": "excluded",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_policy_requires_every_control() {
        let mut p = McpToolPolicy { allow_dangerous_tools: true, authz_policy: "operator-key".into(), sandbox_profile: "container".into(), audit_redaction: false };
        assert!(!p.allows("write_file"));
        p.audit_redaction = true;
        assert!(p.allows("write_file"));
        assert!(p.allows("format_json"));
    }

    #[test]
    fn receipt_excludes_argument_content() {
        let r = McpToolPolicy::default().receipt("read_secret", "denied", 2);
        assert_eq!(r["argument_content"], "excluded");
        assert!(r.get("arguments").is_none());
        assert!(!r.to_string().contains("GDPR_CANARY_TOOL_INPUT"));
        assert_eq!(tool_risk_label("drone_control"), "physical_world");
    }
}
