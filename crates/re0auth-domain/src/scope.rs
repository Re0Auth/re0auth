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

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_scope_is_idempotent(raw in r"[\s\S]{0,256}") {
            let once = parse_scope(&raw);
            prop_assert_eq!(parse_scope(&once.join(" ")), once);
        }

        #[test]
        fn parsed_scopes_are_sorted_and_unique(raw in r"[\s\S]{0,256}") {
            let scopes = parse_scope(&raw);
            prop_assert!(scopes.windows(2).all(|pair| pair[0] < pair[1]));
        }

        #[test]
        fn a_scope_set_is_a_subset_of_itself(raw in r"[\s\S]{0,256}") {
            let scopes = parse_scope(&raw);
            prop_assert!(is_subset(&scopes, &scopes));
        }

        #[test]
        fn a_scope_set_is_a_subset_of_any_superset(
            raw in r"[\s\S]{0,128}",
            extra in r"[\s\S]{0,128}",
        ) {
            let requested = parse_scope(&raw);
            let mut allowed = requested.clone();
            allowed.extend(parse_scope(&extra));
            prop_assert!(is_subset(&requested, &allowed));
        }
    }
}
