/// Domain allowlist for the proxy.
///
/// Supports exact matches and wildcard prefix patterns (`*.example.com`).
#[derive(Debug, Clone)]
pub struct DomainAllowlist {
    patterns: Vec<AllowlistEntry>,
}

#[derive(Debug, Clone)]
enum AllowlistEntry {
    Exact(String),
    Wildcard(String), // stores the suffix (e.g., "example.com" for "*.example.com")
}

impl DomainAllowlist {
    /// Create a new allowlist from domain pattern strings.
    ///
    /// Patterns can be exact (`"registry.npmjs.org"`) or wildcard (`"*.npmjs.org"`).
    pub fn new(patterns: &[String]) -> Result<Self, String> {
        let patterns = patterns
            .iter()
            .map(|pattern| {
                let pattern = pattern.trim().trim_end_matches('.');
                if let Some(suffix) = pattern.strip_prefix("*.") {
                    let suffix = canonical_hostname(suffix)?;
                    Ok(AllowlistEntry::Wildcard(suffix))
                } else {
                    Ok(AllowlistEntry::Exact(canonical_hostname(pattern)?))
                }
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { patterns })
    }

    /// Check whether a domain is allowed.
    pub fn is_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = canonical_hostname(domain.trim_end_matches('.')) else {
            return false;
        };
        self.patterns.iter().any(|entry| match entry {
            AllowlistEntry::Exact(d) => domain == *d,
            AllowlistEntry::Wildcard(suffix) => {
                domain == *suffix || domain.ends_with(&format!(".{suffix}"))
            }
        })
    }

    /// Check if the allowlist is empty (no domains allowed).
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

fn canonical_hostname(host: &str) -> Result<String, String> {
    let host = idna::domain_to_ascii(host)
        .map_err(|_| format!("invalid IDNA hostname '{host}'"))?
        .to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || host.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!("invalid hostname '{host}'"));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(format!("invalid hostname '{host}'"));
        }
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_allow_exact_match() {
        let al = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]).unwrap();
        assert!(al.is_allowed("registry.npmjs.org"));
        assert!(!al.is_allowed("evil.com"));
    }

    #[test]
    fn test_should_allow_wildcard_match() {
        let al = DomainAllowlist::new(&["*.npmjs.org".to_owned()]).unwrap();
        assert!(al.is_allowed("registry.npmjs.org"));
        assert!(al.is_allowed("npmjs.org"));
        assert!(!al.is_allowed("evil.com"));
    }

    #[test]
    fn test_should_be_case_insensitive() {
        let al = DomainAllowlist::new(&["Registry.NPMJS.org".to_owned()]).unwrap();
        assert!(al.is_allowed("registry.npmjs.org"));
        assert!(al.is_allowed("REGISTRY.NPMJS.ORG"));
    }

    #[test]
    fn test_should_handle_empty_allowlist() {
        let al = DomainAllowlist::new(&[]).unwrap();
        assert!(!al.is_allowed("anything.com"));
        assert!(al.is_empty());
    }
}
