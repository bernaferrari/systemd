// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/keyutil/keyutil.c
//
// Operations on private keys and certificates (validate, extract, pkcs7).
// Supports file, provider, and engine key sources.

// ── Types ─────────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, i32>;

/// Key source type (how the private key is accessed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySourceType {
    File,
    Provider,
    Engine,
}

impl Default for KeySourceType {
    fn default() -> Self {
        KeySourceType::File
    }
}

impl KeySourceType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "file" => Some(KeySourceType::File),
            "provider" => Some(KeySourceType::Provider),
            "engine" => Some(KeySourceType::Engine),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KeySourceType::File => "file",
            KeySourceType::Provider => "provider",
            KeySourceType::Engine => "engine",
        }
    }
}

/// Certificate source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateSourceType {
    File,
    Provider,
}

impl Default for CertificateSourceType {
    fn default() -> Self {
        CertificateSourceType::File
    }
}

impl CertificateSourceType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "file" => Some(CertificateSourceType::File),
            "provider" => Some(CertificateSourceType::Provider),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CertificateSourceType::File => "file",
            CertificateSourceType::Provider => "provider",
        }
    }
}

/// Verb (subcommand) for the keyutil tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUtilVerb {
    Validate,
    ExtractPublic,
    ExtractCertificate,
    Pkcs7,
    Help,
}

impl KeyUtilVerb {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "validate" => Some(KeyUtilVerb::Validate),
            "extract-public" => Some(KeyUtilVerb::ExtractPublic),
            "public" => Some(KeyUtilVerb::ExtractPublic),
            "extract-certificate" => Some(KeyUtilVerb::ExtractCertificate),
            "pkcs7" => Some(KeyUtilVerb::Pkcs7),
            "help" => Some(KeyUtilVerb::Help),
            _ => None,
        }
    }
}

/// Parsed command-line arguments for `systemd-keyutil`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUtilArgs {
    pub private_key: Option<String>,
    pub private_key_source_type: KeySourceType,
    pub private_key_source: Option<String>,
    pub certificate: Option<String>,
    pub certificate_source_type: CertificateSourceType,
    pub certificate_source: Option<String>,
    pub signature: Option<String>,
    pub content: Option<String>,
    pub hash_algorithm: Option<String>,
    pub output: Option<String>,
}

impl Default for KeyUtilArgs {
    fn default() -> Self {
        Self {
            private_key: None,
            private_key_source_type: KeySourceType::File,
            private_key_source: None,
            certificate: None,
            certificate_source_type: CertificateSourceType::File,
            certificate_source: None,
            signature: None,
            content: None,
            hash_algorithm: None,
            output: None,
        }
    }
}

impl KeyUtilArgs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate_required_for_validate(&self) -> Result<()> {
        if self.certificate.is_none() {
            return Err(-libc::EINVAL);
        }
        if self.private_key.is_none() {
            return Err(-libc::EINVAL);
        }
        Ok(())
    }

    pub fn validate_required_for_extract_certificate(&self) -> Result<()> {
        if self.certificate.is_none() {
            return Err(-libc::EINVAL);
        }
        Ok(())
    }

    pub fn validate_required_for_pkcs7(&self) -> Result<()> {
        if self.certificate.is_none() {
            return Err(-libc::EINVAL);
        }
        if self.signature.is_none() {
            return Err(-libc::EINVAL);
        }
        if self.output.is_none() {
            return Err(-libc::EINVAL);
        }
        Ok(())
    }

    pub fn has_certificate_or_private_key(&self) -> bool {
        self.certificate.is_some() || self.private_key.is_some()
    }

    pub fn validate_private_key_source_needs_certificate(&self) -> Result<()> {
        if self.private_key_source.is_some() && self.certificate.is_none() {
            return Err(-libc::EINVAL);
        }
        Ok(())
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parse a key source string (e.g., "provider:myprovider" or "engine:pkcs11").
pub fn parse_key_source(s: &str) -> Result<(KeySourceType, &str)> {
    if let Some(rest) = s.strip_prefix("provider:") {
        Ok((KeySourceType::Provider, rest))
    } else if let Some(rest) = s.strip_prefix("engine:") {
        Ok((KeySourceType::Engine, rest))
    } else {
        Ok((KeySourceType::File, s))
    }
}

/// Parse a certificate source string.
pub fn parse_certificate_source(s: &str) -> Result<(CertificateSourceType, &str)> {
    if let Some(rest) = s.strip_prefix("provider:") {
        Ok((CertificateSourceType::Provider, rest))
    } else {
        Ok((CertificateSourceType::File, s))
    }
}

/// Parse command-line arguments for `systemd-keyutil`.
pub fn parse_keyutil_args(args: &[&str]) -> Result<KeyUtilArgs> {
    let mut result = KeyUtilArgs::new();
    let mut i = 0;

    while i < args.len() {
        match args[i] {
            "--help" | "-h" => return Err(0),
            "--version" => return Err(0),
            "--private-key" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.private_key = Some(args[i].to_string());
            }
            "--private-key-source" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                let (source_type, source) = parse_key_source(args[i])?;
                result.private_key_source_type = source_type;
                if source_type != KeySourceType::File {
                    result.private_key_source = Some(source.to_string());
                }
            }
            "--certificate" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.certificate = Some(args[i].to_string());
            }
            "--certificate-source" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                let (source_type, source) = parse_certificate_source(args[i])?;
                result.certificate_source_type = source_type;
                if source_type != CertificateSourceType::File {
                    result.certificate_source = Some(source.to_string());
                }
            }
            "--signature" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.signature = Some(args[i].to_string());
            }
            "--content" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.content = Some(args[i].to_string());
            }
            "--hash-algorithm" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.hash_algorithm = Some(args[i].to_string());
            }
            "--output" => {
                i += 1;
                if i >= args.len() {
                    return Err(-libc::EINVAL);
                }
                result.output = Some(args[i].to_string());
            }
            s if s.starts_with('-') => return Err(-libc::EINVAL),
            _ => {}
        }
        i += 1;
    }

    result.validate_private_key_source_needs_certificate()?;
    Ok(result)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = KeyUtilArgs::new();
        assert!(args.private_key.is_none());
        assert!(args.certificate.is_none());
        assert_eq!(args.private_key_source_type, KeySourceType::File);
        assert_eq!(args.certificate_source_type, CertificateSourceType::File);
    }

    #[test]
    fn test_validate_missing_certificate() {
        let args = KeyUtilArgs::new();
        assert!(args.validate_required_for_validate().is_err());
    }

    #[test]
    fn test_validate_missing_private_key() {
        let args = KeyUtilArgs {
            certificate: Some("cert.pem".into()),
            ..Default::default()
        };
        assert!(args.validate_required_for_validate().is_err());
    }

    #[test]
    fn test_validate_ok() {
        let args = KeyUtilArgs {
            certificate: Some("cert.pem".into()),
            private_key: Some("key.pem".into()),
            ..Default::default()
        };
        assert!(args.validate_required_for_validate().is_ok());
    }

    #[test]
    fn test_pkcs7_missing_signature() {
        let args = KeyUtilArgs {
            certificate: Some("cert.pem".into()),
            ..Default::default()
        };
        assert!(args.validate_required_for_pkcs7().is_err());
    }

    #[test]
    fn test_pkcs7_missing_output() {
        let args = KeyUtilArgs {
            certificate: Some("cert.pem".into()),
            signature: Some("sig.bin".into()),
            ..Default::default()
        };
        assert!(args.validate_required_for_pkcs7().is_err());
    }

    #[test]
    fn test_pkcs7_ok() {
        let args = KeyUtilArgs {
            certificate: Some("cert.pem".into()),
            signature: Some("sig.bin".into()),
            output: Some("out.p7b".into()),
            ..Default::default()
        };
        assert!(args.validate_required_for_pkcs7().is_ok());
    }

    #[test]
    fn test_parse_key_source_file() {
        let (ty, rest) = parse_key_source("/path/to/key.pem").unwrap();
        assert_eq!(ty, KeySourceType::File);
        assert_eq!(rest, "/path/to/key.pem");
    }

    #[test]
    fn test_parse_key_source_provider() {
        let (ty, rest) = parse_key_source("provider:myprovider").unwrap();
        assert_eq!(ty, KeySourceType::Provider);
        assert_eq!(rest, "myprovider");
    }

    #[test]
    fn test_parse_key_source_engine() {
        let (ty, rest) = parse_key_source("engine:pkcs11").unwrap();
        assert_eq!(ty, KeySourceType::Engine);
        assert_eq!(rest, "pkcs11");
    }

    #[test]
    fn test_parse_certificate_source_file() {
        let (ty, rest) = parse_certificate_source("/path/to/cert.pem").unwrap();
        assert_eq!(ty, CertificateSourceType::File);
        assert_eq!(rest, "/path/to/cert.pem");
    }

    #[test]
    fn test_parse_certificate_source_provider() {
        let (ty, rest) = parse_certificate_source("provider:myprov").unwrap();
        assert_eq!(ty, CertificateSourceType::Provider);
        assert_eq!(rest, "myprov");
    }

    #[test]
    fn test_has_certificate_or_key() {
        let args = KeyUtilArgs::new();
        assert!(!args.has_certificate_or_private_key());
        let args2 = KeyUtilArgs {
            certificate: Some("c.pem".into()),
            ..Default::default()
        };
        assert!(args2.has_certificate_or_private_key());
        let args3 = KeyUtilArgs {
            private_key: Some("k.pem".into()),
            ..Default::default()
        };
        assert!(args3.has_certificate_or_private_key());
    }

    #[test]
    fn test_key_source_type_roundtrip() {
        for st in [
            KeySourceType::File,
            KeySourceType::Provider,
            KeySourceType::Engine,
        ] {
            assert_eq!(KeySourceType::from_str(st.as_str()), Some(st));
        }
    }

    #[test]
    fn test_certificate_source_type_roundtrip() {
        for st in [CertificateSourceType::File, CertificateSourceType::Provider] {
            assert_eq!(CertificateSourceType::from_str(st.as_str()), Some(st));
        }
    }

    #[test]
    fn test_verb_from_str() {
        assert_eq!(
            KeyUtilVerb::from_str("validate"),
            Some(KeyUtilVerb::Validate)
        );
        assert_eq!(
            KeyUtilVerb::from_str("extract-public"),
            Some(KeyUtilVerb::ExtractPublic)
        );
        assert_eq!(
            KeyUtilVerb::from_str("public"),
            Some(KeyUtilVerb::ExtractPublic)
        );
        assert_eq!(
            KeyUtilVerb::from_str("extract-certificate"),
            Some(KeyUtilVerb::ExtractCertificate)
        );
        assert_eq!(KeyUtilVerb::from_str("pkcs7"), Some(KeyUtilVerb::Pkcs7));
        assert_eq!(KeyUtilVerb::from_str("invalid"), None);
    }

    #[test]
    fn test_validate_extract_certificate_needs_cert() {
        let args = KeyUtilArgs::new();
        assert!(args.validate_required_for_extract_certificate().is_err());
        let args2 = KeyUtilArgs {
            certificate: Some("c.pem".into()),
            ..Default::default()
        };
        assert!(args2.validate_required_for_extract_certificate().is_ok());
    }

    #[test]
    fn test_private_key_source_needs_certificate() {
        let args = KeyUtilArgs {
            private_key_source: Some("prov".into()),
            certificate: None,
            ..Default::default()
        };
        assert!(
            args.validate_private_key_source_needs_certificate()
                .is_err()
        );
    }
}
