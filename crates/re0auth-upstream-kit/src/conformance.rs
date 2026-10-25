use crate::discovery::{
    ACCOUNT_SCOPE, Discovery, PROTOCOL_VERSION, TokenClass, is_canonical_schema, is_canonical_scope,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.ok)
    }

    pub fn failures(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|check| !check.ok)
    }
}

pub fn check_discovery(discovery: &Discovery) -> Report {
    let mut checks = Vec::new();
    let mut push = |name: &str, ok: bool, detail: String| {
        checks.push(Check {
            name: name.to_string(),
            ok,
            detail,
        });
    };

    push(
        "protocol_version",
        discovery.re0auth_upstream_version == PROTOCOL_VERSION,
        format!(
            "expected {PROTOCOL_VERSION}, got {}",
            discovery.re0auth_upstream_version
        ),
    );
    push(
        "account_scope",
        discovery
            .scopes_supported
            .iter()
            .any(|scope| scope == ACCOUNT_SCOPE),
        format!("{ACCOUNT_SCOPE} must be present"),
    );
    push(
        "token_class",
        matches!(
            discovery.token_class,
            TokenClass::Revocable | TokenClass::LongLived
        ),
        format!("{:?}", discovery.token_class),
    );

    for resource in &discovery.resources {
        push(
            &format!("schema:{}", resource.name),
            is_canonical_schema(&resource.schema),
            resource.schema.clone(),
        );
        push(
            &format!("scope:{}", resource.name),
            is_canonical_scope(&resource.scope),
            resource.scope.clone(),
        );
        push(
            &format!("scope_listed:{}", resource.name),
            discovery
                .scopes_supported
                .iter()
                .any(|scope| scope == &resource.scope),
            resource.scope.clone(),
        );
    }

    for scope in &discovery.scopes_supported {
        push(
            &format!("scope:{scope}"),
            scope == ACCOUNT_SCOPE || is_canonical_scope(scope),
            scope.clone(),
        );
    }

    push(
        "cascade_endpoint",
        discovery
            .oauth
            .cascade_revocation_endpoint
            .as_deref()
            .map(|endpoint| endpoint.ends_with("/oauth/cascade_revocation"))
            .unwrap_or(true),
        discovery
            .oauth
            .cascade_revocation_endpoint
            .clone()
            .unwrap_or_else(|| "not advertised".to_string()),
    );

    Report { checks }
}
