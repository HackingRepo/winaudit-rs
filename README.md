[![Crates.io](https://img.shields.io/crates/v/winaudit.svg)](https://crates.io/crates/winaudit)
[![Docs.rs](https://docs.rs/winaudit/badge.svg)](https://docs.rs/winaudit)


# Overview
My winaudit crate provide Security Checks for Windows Systems this can be used for Building a Windows Auditor framework or Security Checks.
# Usage Example

By example if we would to check is bitdefender running and installed

First we need to add the crate to current project.

```powershell
PS> cargo add winaudit
```

And in main.rs 
```rust
use winaudit::is_bitdefender_installed_and_enabled;
fn main() {
    let is_bitdefender_installed = match is_bitdefender_installed_and_enabled() {
        Ok(b) => b,
        Err(e) => eprintln!("Something wrong! {:?}", e)
    };
    if is_bitdefender_installed {
        println!("Bitdefender is installed and enabled");
    } else {
        println!("Bitdefender is not installed or enabled");
    }
}
```

# Contributions
If you want to contribute fill free to open an issue or pull request on this repo [winaudit](https://github.com/HackingRepo/winaudit-rs)

# Documentations and Examples
All examples and docs in [docs.rs](https://docs.rs/crate/winaudit/latest).
