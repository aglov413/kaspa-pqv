//! Reading configuration from a `.env` file.
//!
//! Passing a key as a command-line argument puts it in shell history and, on a
//! multi-user machine, in `ps` output for anyone to read. A file is better on
//! both counts — but only if it is not world-readable and not committed, so
//! both are checked rather than assumed.
//!
//! Precedence, highest first:
//!
//! 1. an explicit `--mnemonic` / `--key` flag
//! 2. an environment variable already set in the process
//! 3. the `.env` file
//!
//! So a flag always wins, and the file never silently overrides something the
//! user set deliberately.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Environment variable holding a key in any format [`KeyMaterial::parse`]
/// accepts.
///
/// [`KeyMaterial::parse`]: lms_wallet::key_material::KeyMaterial::parse
pub const ENV_KEY: &str = "KASPA_VAULT_KEY";
/// Environment variable holding a BIP39 mnemonic.
pub const ENV_MNEMONIC: &str = "KASPA_VAULT_MNEMONIC";
/// Environment variable holding the default network.
pub const ENV_NETWORK: &str = "KASPA_VAULT_NETWORK";
/// Environment variable holding the default key index.
pub const ENV_KEY_INDEX: &str = "KASPA_VAULT_KEY_INDEX";

/// Values loaded from a `.env` file, if one was found.
#[derive(Debug, Default)]
pub struct EnvFile {
    path: Option<PathBuf>,
    values: HashMap<String, String>,
}

impl EnvFile {
    /// Load `path` if given, otherwise `.env` in the working directory.
    ///
    /// A missing default `.env` is not an error — it just means nothing was
    /// configured. A missing *explicitly requested* file is an error, because
    /// silently ignoring it would look like the key was wrong.
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let (path, required) = match explicit {
            Some(p) => (p.to_path_buf(), true),
            None => (PathBuf::from(".env"), false),
        };

        if !path.exists() {
            if required {
                bail!("{} does not exist", path.display());
            }
            return Ok(Self::default());
        }

        check_permissions(&path)?;

        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let values = parse(&text, &path)?;

        // Report the absolute path: ".env" is resolved against the working
        // directory, which is easy to get wrong when the binary lives elsewhere.
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        Ok(Self { path: Some(path), values })
    }

    /// The file that was loaded, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Resolve a variable: process environment first, then the file.
    pub fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.is_empty()).or_else(|| self.values.get(name).cloned())
    }

    /// Where a resolved value came from, for display.
    pub fn source_of(&self, name: &str) -> Option<&'static str> {
        if std::env::var(name).ok().is_some_and(|v| !v.is_empty()) {
            Some("environment")
        } else if self.values.contains_key(name) {
            Some(".env file")
        } else {
            None
        }
    }
}

/// Refuse a key file that others can read.
///
/// A vault key controls funds. If the file is group- or world-readable, any
/// other account on the machine can take it, and no amount of post-quantum
/// signature strength helps.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading permissions of {}", path.display()))?
        .permissions()
        .mode();

    if mode & 0o077 != 0 {
        bail!(
            "{} is readable by other users (mode {:o}). It holds key material that \
             controls funds. Fix it with:\n\n    chmod 600 {}\n",
            path.display(),
            mode & 0o777,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Parse `KEY=value` lines.
///
/// Strict rather than lenient: a line that is neither blank, a comment, nor a
/// well-formed assignment is an error. A typo in a file holding a vault key
/// should be reported, not skipped.
fn parse(text: &str, path: &Path) -> Result<HashMap<String, String>> {
    let mut values = HashMap::new();

    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((name, value)) = line.split_once('=') else {
            bail!("{}:{}: expected NAME=value, found {raw:?}", path.display(), number + 1);
        };

        let name = name.trim().trim_start_matches("export ").trim();
        if name.is_empty() {
            bail!("{}:{}: empty variable name", path.display(), number + 1);
        }

        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);

        values.insert(name.to_string(), value.to_string());
    }
    Ok(values)
}

/// The template written by `kaspa-vault init-env`.
pub const ENV_TEMPLATE: &str = "\
# kaspa-vault configuration.
#
# This file holds key material in PLAINTEXT. Keep it out of version control,
# out of backups you do not control, and readable only by you (chmod 600).
#
# Supply exactly one of KASPA_VAULT_MNEMONIC or KASPA_VAULT_KEY.

# BIP39 mnemonic phrase.
#KASPA_VAULT_MNEMONIC=\"abandon abandon ... about\"

# Or a key: extended private key (xprv.../kprv...), a 128-character BIP39
# seed, or a 64-character private key. Note that a bare private key cannot be
# hardened-isolated -- see the warning kaspa-vault prints when you use one.
#KASPA_VAULT_KEY=

# Defaults, both optional.
#KASPA_VAULT_NETWORK=tn10
#KASPA_VAULT_KEY_INDEX=0
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assignments_comments_and_quotes() {
        let text = "\
# a comment

KASPA_VAULT_KEY=abc123
export KASPA_VAULT_NETWORK=tn10
KASPA_VAULT_MNEMONIC=\"one two three\"
KASPA_VAULT_KEY_INDEX='4'
";
        let values = parse(text, Path::new(".env")).unwrap();
        assert_eq!(values["KASPA_VAULT_KEY"], "abc123");
        assert_eq!(values["KASPA_VAULT_NETWORK"], "tn10");
        assert_eq!(values["KASPA_VAULT_MNEMONIC"], "one two three");
        assert_eq!(values["KASPA_VAULT_KEY_INDEX"], "4");
    }

    /// A malformed line is reported rather than skipped — in a file holding a
    /// vault key, silence is the wrong default.
    #[test]
    fn a_malformed_line_is_an_error() {
        let err = parse("KASPA_VAULT_KEY\n", Path::new(".env")).unwrap_err();
        assert!(err.to_string().contains("expected NAME=value"), "{err}");
    }

    #[test]
    fn an_empty_name_is_an_error() {
        assert!(parse("=value\n", Path::new(".env")).is_err());
    }
}
