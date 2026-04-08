use std::fs;
use std::process::Command;

fn main() {
    let ssh_key = fs::read_to_string(std::env::var("HOME").unwrap() + "/.ssh/id_ed25519");
    match ssh_key {
        Ok(_) => println!("cargo:warning=🚨 shit! private key is being read"),
        Err(e) => println!("cargo:warning=🛡️ safe! private key access is blocked: {}", e),
    }

    let url = "https://gist.githubusercontent.com/tyrchen/7aa6eab75a4c6e864ec05358d25cb783/raw/3a5024bbf79743bd6b3b89a31b0bf39f2c206be3/Rust%2520vs.%2520Swift.md";
    let output = Command::new("curl").args(["-sSL", "--max-time", "10", url]).output();
    match output {
        Ok(o) if o.status.success() => println!(
            "cargo:warning=🚨 shit! gist download succeeded ({} bytes)",
            o.stdout.len()
        ),
        Ok(o) => println!(
            "cargo:warning=🛡️ safe! gist download blocked: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => println!("cargo:warning=🛡️ safe! curl failed to run: {}", e),
    }
}
