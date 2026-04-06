use std::{fmt, path::Path};

use serde::{Deserialize, Serialize};

/// Supported language ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Ecosystem {
    Node,
    Rust,
    Python,
    Elixir,
    Java,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node => write!(f, "node"),
            Self::Rust => write!(f, "rust"),
            Self::Python => write!(f, "python"),
            Self::Elixir => write!(f, "elixir"),
            Self::Java => write!(f, "java"),
        }
    }
}

impl Ecosystem {
    /// All known ecosystems.
    pub const ALL: [Self; 5] = [
        Self::Node,
        Self::Rust,
        Self::Python,
        Self::Elixir,
        Self::Java,
    ];
}

impl std::str::FromStr for Ecosystem {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "node" | "nodejs" | "js" | "javascript" => Ok(Self::Node),
            "rust" | "rs" => Ok(Self::Rust),
            "python" | "py" => Ok(Self::Python),
            "elixir" | "ex" => Ok(Self::Elixir),
            "java" | "jvm" => Ok(Self::Java),
            _ => Err(format!("unknown ecosystem: {s}")),
        }
    }
}

/// Detect the ecosystem from the command being run.
fn detect_from_command(command: &str) -> Option<Ecosystem> {
    // Extract basename from the command (handles full paths)
    let basename = Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);

    match basename {
        // Node.js
        "node" | "npm" | "npx" | "yarn" | "pnpm" | "bun" => Some(Ecosystem::Node),
        // Rust
        "cargo" | "rustc" | "rustup" => Some(Ecosystem::Rust),
        // Python
        "python" | "python3" | "pip" | "pip3" | "uv" | "poetry" | "pdm" | "rye" => {
            Some(Ecosystem::Python)
        }
        // Elixir
        "mix" | "elixir" | "iex" => Some(Ecosystem::Elixir),
        // Java
        "java" | "javac" | "mvn" | "gradle" | "gradlew" => Some(Ecosystem::Java),
        _ => None,
    }
}

/// Detect the ecosystem from marker files in the working directory.
fn detect_from_files(pwd: &Path) -> Option<Ecosystem> {
    // Check in priority order — more specific markers first
    let markers: &[(&str, Ecosystem)] = &[
        ("Cargo.toml", Ecosystem::Rust),
        ("mix.exs", Ecosystem::Elixir),
        ("package.json", Ecosystem::Node),
        ("pyproject.toml", Ecosystem::Python),
        ("setup.py", Ecosystem::Python),
        ("requirements.txt", Ecosystem::Python),
        ("Pipfile", Ecosystem::Python),
        ("pom.xml", Ecosystem::Java),
        ("build.gradle", Ecosystem::Java),
        ("build.gradle.kts", Ecosystem::Java),
    ];

    for (marker, ecosystem) in markers {
        if pwd.join(marker).exists() {
            return Some(*ecosystem);
        }
    }
    None
}

/// Detect the ecosystem from command name and working directory.
///
/// Returns `None` if no ecosystem could be determined.
pub fn detect(command: &str, pwd: &Path) -> Option<Ecosystem> {
    detect_from_command(command).or_else(|| detect_from_files(pwd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_detect_node_from_npm() {
        assert_eq!(detect_from_command("npm"), Some(Ecosystem::Node));
        assert_eq!(detect_from_command("yarn"), Some(Ecosystem::Node));
        assert_eq!(detect_from_command("pnpm"), Some(Ecosystem::Node));
        assert_eq!(detect_from_command("bun"), Some(Ecosystem::Node));
    }

    #[test]
    fn test_should_detect_rust_from_cargo() {
        assert_eq!(detect_from_command("cargo"), Some(Ecosystem::Rust));
    }

    #[test]
    fn test_should_detect_python_from_pip() {
        assert_eq!(detect_from_command("pip"), Some(Ecosystem::Python));
        assert_eq!(detect_from_command("uv"), Some(Ecosystem::Python));
        assert_eq!(detect_from_command("poetry"), Some(Ecosystem::Python));
    }

    #[test]
    fn test_should_detect_elixir_from_mix() {
        assert_eq!(detect_from_command("mix"), Some(Ecosystem::Elixir));
    }

    #[test]
    fn test_should_detect_java_from_gradle() {
        assert_eq!(detect_from_command("gradle"), Some(Ecosystem::Java));
        assert_eq!(detect_from_command("gradlew"), Some(Ecosystem::Java));
        assert_eq!(detect_from_command("mvn"), Some(Ecosystem::Java));
    }

    #[test]
    fn test_should_return_none_for_unknown() {
        assert_eq!(detect_from_command("unknown-tool"), None);
    }

    #[test]
    fn test_should_detect_from_full_path() {
        assert_eq!(
            detect_from_command("/usr/local/bin/npm"),
            Some(Ecosystem::Node)
        );
    }

    #[test]
    fn test_should_parse_ecosystem_from_str() {
        assert_eq!("node".parse::<Ecosystem>(), Ok(Ecosystem::Node));
        assert_eq!("js".parse::<Ecosystem>(), Ok(Ecosystem::Node));
        assert_eq!("rust".parse::<Ecosystem>(), Ok(Ecosystem::Rust));
        assert_eq!("py".parse::<Ecosystem>(), Ok(Ecosystem::Python));
        assert_eq!("ex".parse::<Ecosystem>(), Ok(Ecosystem::Elixir));
        assert_eq!("jvm".parse::<Ecosystem>(), Ok(Ecosystem::Java));
        assert!("unknown".parse::<Ecosystem>().is_err());
    }
}
