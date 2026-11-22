//! `Debug` helpers that keep secrets out of logs and error messages.
//!
//! A config struct that holds a secret (a node API key, an auth key, a signing key, a URL
//! with a password in it) implements `Debug` by hand with these helpers, so `{:?}` of a config
//! shows its shape and every non-secret value but never the secret itself.

use std::borrow::Cow;
use std::fmt;

/// `Debug` of an optional secret: `<redacted>` when it is set, `None` when it is not.
pub struct Secret<'a, T>(pub &'a Option<T>);

impl<T> fmt::Debug for Secret<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(_) => f.write_str("<redacted>"),
            None => f.write_str("None"),
        }
    }
}

/// `Debug` of a URL: the string, with any credentials in it shown as `<redacted>`
/// (see [`url_without_credentials`]).
pub struct Url<'a>(pub &'a str);

impl fmt::Debug for Url<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&url_without_credentials(self.0), f)
    }
}

/// `url` with the user info of its authority (`user@`, `user:password@`) replaced by
/// `<redacted>`. The authority runs from after `scheme://` (or from the start when there is
/// no scheme) to the first `/`, `?` or `#`, and its last `@` ends the user info, as URL
/// parsers read it. Without an `@` there the URL is returned unchanged.
pub fn url_without_credentials(url: &str) -> Cow<'_, str> {
    let authority_start = url.find("://").map_or(0, |i| i + 3);
    let rest = &url[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => {
            let (before, after) = (&url[..authority_start], &rest[at..]);
            Cow::Owned(format!("{before}<redacted>{after}"))
        }
        None => Cow::Borrowed(url),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_prints_as_redacted_or_none() {
        assert_eq!(format!("{:?}", Secret(&Some("hunter2"))), "<redacted>");
        assert_eq!(format!("{:#?}", Secret(&Some([7u8; 32]))), "<redacted>");
        assert_eq!(format!("{:?}", Secret(&None::<String>)), "None");
    }

    #[test]
    fn a_url_loses_its_credentials_and_nothing_else() {
        let cases = [
            ("https://node.example:9053/", "https://node.example:9053/"),
            ("http://[::1]:9053/info", "http://[::1]:9053/info"),
            (
                "http://user:pass@node.example:9053/info",
                "http://<redacted>@node.example:9053/info",
            ),
            ("http://user@node.example", "http://<redacted>@node.example"),
            (
                "http://us@er:p@ss@node.example/x",
                "http://<redacted>@node.example/x",
            ),
            (
                "http://node.example/a@b?c=d@e#f@g",
                "http://node.example/a@b?c=d@e#f@g",
            ),
            (
                "user:pass@node.example:9053",
                "<redacted>@node.example:9053",
            ),
            ("", ""),
        ];
        for (url, shown) in cases {
            assert_eq!(url_without_credentials(url), shown, "{url}");
        }
        assert_eq!(
            format!("{:?}", Url("http://u:p@node.example/")),
            r#""http://<redacted>@node.example/""#
        );
    }

    /// The store's node configs (`[ergo.scanner]` and the tracker scanner's) never print
    /// their API key or a password in their node URL.
    #[test]
    fn node_configs_never_print_their_secrets() {
        let node_url = "https://scan:FAKE-URL-PASSWORD@node.example:9053".to_string();
        let api_key = Some("FAKE-NODE-API-KEY".to_string());
        let scanner = crate::ergo_scanner::NodeConfig {
            start_height: Some(1),
            reserve_contract_p2s: None,
            token_reserve_contract_p2s: None,
            tracker_nft_id: None,
            node_url: node_url.clone(),
            scan_name: None,
            api_key: api_key.clone(),
        };
        let tracker = crate::tracker_scanner::TrackerNodeConfig {
            start_height: Some(1),
            tracker_nft_id: None,
            node_url,
            scan_name: None,
            api_key,
        };
        let printed = [
            format!("{scanner:?}"),
            format!("{scanner:#?}"),
            format!("{tracker:?}"),
            format!("{tracker:#?}"),
        ];
        for printed in printed {
            assert!(!printed.contains("FAKE-NODE-API-KEY"), "{printed}");
            assert!(!printed.contains("FAKE-URL-PASSWORD"), "{printed}");
            assert!(
                printed.contains("<redacted>@node.example:9053"),
                "{printed}"
            );
            assert!(printed.contains("api_key: <redacted>"), "{printed}");
        }
        let unset = crate::tracker_scanner::TrackerNodeConfig {
            api_key: None,
            ..tracker
        };
        assert!(format!("{unset:?}").contains("api_key: None"));
    }
}
