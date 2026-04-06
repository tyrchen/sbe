use std::{
    env,
    path::{Path, PathBuf},
};

use super::{DomainPattern, SandboxProfile, common_allow_exec, common_deny_exec, common_deny_read};

/// Default sandbox profile for the Java ecosystem.
pub fn java_profile(home: &Path, pwd: &Path) -> SandboxProfile {
    let mut allow_exec = common_allow_exec();
    allow_exec.extend([
        PathBuf::from("/usr/bin/java"),
        PathBuf::from("/usr/libexec/java_home"),
        PathBuf::from("/opt/homebrew/opt/openjdk"),
        home.join(".sdkman"),
    ]);

    // If JAVA_HOME is set, allow execution from it
    if let Ok(java_home) = env::var("JAVA_HOME") {
        allow_exec.push(PathBuf::from(java_home));
    }

    SandboxProfile {
        name: "java".to_owned(),
        allow_write: vec![
            pwd.to_path_buf(),
            home.join(".m2/repository"),
            home.join(".gradle/caches"),
            home.join(".gradle/wrapper"),
            pwd.join(".gradle"),
            pwd.join("build"),
            pwd.join("target"),
        ],
        deny_read: common_deny_read(home),
        allow_domains: vec![
            DomainPattern::from("repo1.maven.org"),
            DomainPattern::from("repo.maven.apache.org"),
            DomainPattern::from("plugins.gradle.org"),
            DomainPattern::from("services.gradle.org"),
            DomainPattern::from("downloads.gradle-dn.com"),
            DomainPattern::from("jcenter.bintray.com"),
            DomainPattern::from("github.com"),
            DomainPattern::from("objects.githubusercontent.com"),
        ],
        deny_exec: common_deny_exec(),
        allow_exec,
        enable_proxy: true,
        allow_all_network: false,
        env: Default::default(),
    }
}
