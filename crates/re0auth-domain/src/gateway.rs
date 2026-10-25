//! Gateway request rules. Pure functions: no I/O, no clock.
//!
//! The core never accepts a URL or a raw path from a caller (ADR-0032).
//! These rules are the only place that decides whether a resource descriptor
//! is safe to hand to a connector.

const MAX_RESOURCE_NAME: usize = 64;
const MAX_SUBJECT: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceError {
    Empty,
    TooLong,
    IllegalCharacter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceField {
    Name,
    Subject,
}

impl ResourceError {
    #[must_use]
    pub fn field(self, field: ResourceField) -> InvalidResource {
        InvalidResource { field, error: self }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidResource {
    pub field: ResourceField,
    pub error: ResourceError,
}

impl std::fmt::Display for InvalidResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = match self.field {
            ResourceField::Name => "resource",
            ResourceField::Subject => "subject",
        };
        match self.error {
            ResourceError::Empty => write!(f, "{field} is empty"),
            ResourceError::TooLong => write!(f, "{field} is too long"),
            ResourceError::IllegalCharacter => write!(f, "{field} has an illegal character"),
        }
    }
}

/// Resource names and subjects share the same conservative alphabet.
/// Anything that could change the request target (`/`, `.`, `%`, `\`, `:`) is
/// rejected before the connector sees it.
fn validate(value: &str, max: usize) -> Result<(), ResourceError> {
    if value.is_empty() {
        return Err(ResourceError::Empty);
    }
    if value.len() > max {
        return Err(ResourceError::TooLong);
    }
    if value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
    }) {
        Ok(())
    } else {
        Err(ResourceError::IllegalCharacter)
    }
}

pub fn validate_resource_name(value: &str) -> Result<(), ResourceError> {
    validate(value, MAX_RESOURCE_NAME)
}

pub fn validate_subject(value: &str) -> Result<(), ResourceError> {
    validate(value, MAX_SUBJECT)
}

/// Exact scope membership. Unknown or differently-cased scopes never match.
#[must_use]
pub fn scope_allows(granted: &[String], required: &str) -> bool {
    !required.is_empty() && granted.iter().any(|scope| scope == required)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_safe_resource_names() {
        assert!(validate_resource_name("scores").is_ok());
        assert!(validate_resource_name("best-30").is_ok());
        assert!(validate_resource_name("save_1").is_ok());
    }

    #[test]
    fn rejects_traversal_and_absolute_urls() {
        for value in ["../etc/passwd", "a/b", "a.b", "a%2e%2e", "a\\b", "https:"] {
            assert_eq!(
                validate_resource_name(value),
                Err(ResourceError::IllegalCharacter),
                "{value} must be rejected"
            );
        }
        assert_eq!(validate_resource_name(""), Err(ResourceError::Empty));
        assert_eq!(
            validate_resource_name(&"a".repeat(65)),
            Err(ResourceError::TooLong)
        );
    }

    #[test]
    fn rejects_uppercase_subjects() {
        assert_eq!(
            validate_subject("Player-1"),
            Err(ResourceError::IllegalCharacter)
        );
        assert!(validate_subject("player-1").is_ok());
    }

    #[test]
    fn scope_check_is_exact() {
        let granted = vec!["openid".to_string(), "scores.read".to_string()];
        assert!(scope_allows(&granted, "scores.read"));
        assert!(!scope_allows(&granted, "scores.write"));
        assert!(!scope_allows(&granted, "Scores.read"));
        assert!(!scope_allows(&granted, ""));
    }

    #[test]
    fn invalid_resource_names_which_field() {
        let error = validate_resource_name("../x")
            .expect_err("must reject")
            .field(ResourceField::Name);
        assert_eq!(error.field, ResourceField::Name);
        assert!(error.to_string().contains("resource"));
    }
}
