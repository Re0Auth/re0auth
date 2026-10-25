//! Scope parsing and subset checks. Pure functions only.

#[must_use]
pub fn parse_scope(raw: &str) -> Vec<String> {
    let mut scopes: Vec<String> = raw
        .split_ascii_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

#[must_use]
pub fn is_subset(requested: &[String], allowed: &[String]) -> bool {
    requested
        .iter()
        .all(|scope| allowed.iter().any(|candidate| candidate == scope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_deduplicates_and_sorts() {
        assert_eq!(
            parse_scope("openid  profile openid"),
            vec!["openid".to_string(), "profile".to_string()]
        );
        assert!(parse_scope("   ").is_empty());
    }

    #[test]
    fn subset_check_is_exact() {
        let allowed = vec!["openid".to_string(), "profile".to_string()];
        assert!(is_subset(&["openid".to_string()], &allowed));
        assert!(!is_subset(
            &["openid".to_string(), "admin".to_string()],
            &allowed
        ));
        assert!(!is_subset(&["OpenID".to_string()], &allowed));
    }
}
