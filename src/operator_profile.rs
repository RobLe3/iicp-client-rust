//! Local startup policy for the pre-normative managed operator profile.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ManagedOperatorInput {
    pub mode: String,
    pub authentication_configured: bool,
    pub identity_storage_protected: bool,
    pub auto_update_requested: bool,
    pub update_authenticated: bool,
    pub rollback_verified: bool,
    pub upnp_requested: bool,
    pub tunnel_requested: bool,
    pub upnp_approved: bool,
    pub tunnel_approved: bool,
}

pub fn evaluate_managed_operator(value: &ManagedOperatorInput) -> (bool, &'static str) {
    if value.mode == "convenience" {
        return (true, "convenience_mode");
    }
    if value.mode != "managed" {
        return (false, "invalid_operator_profile");
    }
    let checks = [
        (value.authentication_configured, "authentication_required"),
        (
            value.identity_storage_protected,
            "protected_identity_storage_required",
        ),
        (
            !value.auto_update_requested || value.update_authenticated,
            "authenticated_update_required",
        ),
        (
            !value.auto_update_requested || value.rollback_verified,
            "rollback_required",
        ),
        (
            !value.upnp_requested || value.upnp_approved,
            "upnp_approval_required",
        ),
        (
            !value.tunnel_requested || value.tunnel_approved,
            "tunnel_approval_required",
        ),
    ];
    checks
        .into_iter()
        .find(|(accepted, _)| !accepted)
        .map_or((true, "managed_requirements_met"), |(_, reason)| {
            (false, reason)
        })
}
