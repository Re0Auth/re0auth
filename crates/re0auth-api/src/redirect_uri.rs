//! 重定向地址校验（RFC 6749）

use url::{Host, Url};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RedirectUriError {
    #[error("redirect_uri must be an absolute URI")]
    Malformed,
    #[error("redirect_uri must carry a host")]
    NoHost,
    #[error("redirect_uri must not carry a fragment")]
    Fragment,
    #[error("redirect_uri must not carry credentials")]
    Credentials,
    #[error("redirect_uri must use https unless it targets localhost")]
    Insecure,
    #[error("redirect_uri must use http or https")]
    Scheme,
}

impl RedirectUriError {
    /// 供只收静态字符串的错误渲染器使用
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Malformed => "redirect_uri must be an absolute URI",
            Self::NoHost => "redirect_uri must carry a host",
            Self::Fragment => "redirect_uri must not carry a fragment",
            Self::Credentials => "redirect_uri must not carry credentials",
            Self::Insecure => "redirect_uri must use https unless it targets localhost",
            Self::Scheme => "redirect_uri must use http or https",
        }
    }
}

/// 回环地址是唯一允许明文 http 的场景
pub fn validate(raw: &str) -> Result<(), RedirectUriError> {
    let url = Url::parse(raw).map_err(|_| RedirectUriError::Malformed)?;
    if url.fragment().is_some() {
        return Err(RedirectUriError::Fragment);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RedirectUriError::Credentials);
    }
    let host = url.host().ok_or(RedirectUriError::NoHost)?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(host) => Ok(()),
        "http" => Err(RedirectUriError::Insecure),
        _ => Err(RedirectUriError::Scheme),
    }
}

fn is_loopback(host: Host<&str>) -> bool {
    match host {
        Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_matches_display() {
        for error in [
            RedirectUriError::Malformed,
            RedirectUriError::NoHost,
            RedirectUriError::Fragment,
            RedirectUriError::Credentials,
            RedirectUriError::Insecure,
            RedirectUriError::Scheme,
        ] {
            assert_eq!(error.description(), error.to_string(), "{error:?}");
        }
    }

    #[test]
    fn https_is_the_default() {
        for value in [
            "https://client.example/callback",
            "https://client.example/callback?tenant=a",
            "https://client.example:8443/callback",
        ] {
            assert_eq!(validate(value), Ok(()), "{value} should be accepted");
        }
    }

    #[test]
    fn loopback_may_use_plain_http() {
        for value in [
            "http://localhost:3000/callback",
            "http://127.0.0.1:19090/callback",
            "http://127.5.5.5/callback",
            "http://[::1]:8080/callback",
            "http://LOCALHOST:5173/callback",
        ] {
            assert_eq!(validate(value), Ok(()), "{value} should be accepted");
        }
    }

    #[test]
    fn plain_http_is_rejected_off_loopback() {
        for value in [
            "http://client.example/callback",
            "http://10.0.0.1/callback",
            "http://127.0.0.1.evil.example/callback",
            "http://localhost.evil.example/callback",
        ] {
            assert_eq!(
                validate(value),
                Err(RedirectUriError::Insecure),
                "{value} must not be accepted over plain http"
            );
        }
    }

    #[test]
    fn fragments_are_refused_even_over_https() {
        for value in [
            "https://client.example/callback#token",
            "http://localhost:3000/callback#token",
        ] {
            assert_eq!(validate(value), Err(RedirectUriError::Fragment), "{value}");
        }
    }

    #[test]
    fn credentials_are_refused() {
        for value in [
            "https://user:secret@client.example/callback",
            "https://user@client.example/callback",
        ] {
            assert_eq!(
                validate(value),
                Err(RedirectUriError::Credentials),
                "{value}"
            );
        }
    }

    #[test]
    fn other_schemes_and_opaque_uris_are_refused() {
        for value in ["ftp://client.example/cb", "javascript:alert(1)"] {
            assert!(
                matches!(
                    validate(value),
                    Err(RedirectUriError::Scheme | RedirectUriError::NoHost)
                ),
                "{value} must not be accepted"
            );
        }
        for value in ["not-a-url", "", "//client.example/callback"] {
            assert_eq!(validate(value), Err(RedirectUriError::Malformed), "{value}");
        }
    }
}
