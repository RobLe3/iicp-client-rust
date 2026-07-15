use crate::{ClientConfig, DiscoverOptions, TaskRequest};

/// Canonical prompt-free projection shared by ticketed and legacy discovery.
pub fn project_route_options(request: &TaskRequest, config: &ClientConfig) -> DiscoverOptions {
    let route = request.route_constraints.as_ref();
    DiscoverOptions {
        region: route
            .and_then(|r| r.region.clone())
            .or_else(|| request.constraints.as_ref().and_then(|c| c.region.clone()))
            .or_else(|| config.region.clone()),
        qos: route
            .and_then(|r| r.qos.clone())
            .or_else(|| request.constraints.as_ref().and_then(|c| c.qos.clone())),
        model: route
            .and_then(|r| r.model.clone())
            .or_else(|| request.constraints.as_ref().and_then(|c| c.model.clone())),
        min_reputation: route
            .and_then(|r| r.min_reputation)
            .or_else(|| request.constraints.as_ref().and_then(|c| c.min_reputation)),
        limit: route.and_then(|r| r.limit).or(Some(10)),
        browser_usable_only: route.and_then(|r| r.browser_usable_only),
        profile_request: route
            .and_then(|r| r.profile_request.clone())
            .or_else(|| config.profile_request.clone()),
    }
}
