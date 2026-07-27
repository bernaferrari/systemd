// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-polkit.c

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolkitRequest {
    pub action: String,
    pub interactive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolkitRegistry {
    allowed_actions: Vec<String>,
}

impl PolkitRegistry {
    pub fn new<I>(allowed_actions: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        Self {
            allowed_actions: allowed_actions.into_iter().map(Into::into).collect(),
        }
    }

    pub fn check(&self, request: &PolkitRequest) -> Result<bool, String> {
        Ok(self
            .allowed_actions
            .iter()
            .any(|candidate| candidate == &request.action))
    }
}

pub fn check_polkit_chvt(
    polkit_enabled: bool,
    registry: Option<&PolkitRegistry>,
) -> Result<bool, String> {
    if !polkit_enabled {
        return Ok(true);
    }

    let request = PolkitRequest {
        action: "org.freedesktop.login1.chvt".to_string(),
        interactive: true,
    };

    registry
        .ok_or_else(|| "polkit enabled but no registry configured".to_string())?
        .check(&request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_polkit_allows_chvt() {
        assert_eq!(check_polkit_chvt(false, None), Ok(true));
    }

    #[test]
    fn registry_decides_when_enabled() {
        let registry = PolkitRegistry::new(["org.freedesktop.login1.chvt"]);
        assert_eq!(check_polkit_chvt(true, Some(&registry)), Ok(true));
    }
}
