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
    pub fn new(patterns: &[String]) -> Self {
        let patterns = patterns
            .iter()
            .map(|p| {
                if let Some(suffix) = p.strip_prefix("*.") {
                    AllowlistEntry::Wildcard(suffix.to_lowercase())
                } else {
                    AllowlistEntry::Exact(p.to_lowercase())
                }
            })
            .collect();
        Self { patterns }
    }

    /// Check whether a domain is allowed.
    pub fn is_allowed(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_allow_exact_match() {
        let al = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]);
        assert!(al.is_allowed("registry.npmjs.org"));
        assert!(!al.is_allowed("evil.com"));
    }

    #[test]
    fn test_should_allow_wildcard_match() {
        let al = DomainAllowlist::new(&["*.npmjs.org".to_owned()]);
        assert!(al.is_allowed("registry.npmjs.org"));
        assert!(al.is_allowed("npmjs.org"));
        assert!(!al.is_allowed("evil.com"));
    }

    #[test]
    fn test_should_be_case_insensitive() {
        let al = DomainAllowlist::new(&["Registry.NPMJS.org".to_owned()]);
        assert!(al.is_allowed("registry.npmjs.org"));
        assert!(al.is_allowed("REGISTRY.NPMJS.ORG"));
    }

    #[test]
    fn test_should_handle_empty_allowlist() {
        let al = DomainAllowlist::new(&[]);
        assert!(!al.is_allowed("anything.com"));
        assert!(al.is_empty());
    }
}
