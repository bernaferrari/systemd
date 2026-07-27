// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-setuid.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/nspawn-setuid.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &["change_uid_gid", "change_uid_gid_raw", "spawn_getent"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub supplementary_gids: Vec<u32>,
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_setuid",
        source_path: SOURCE_PATH,
        source_lines: 233,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn spawn_getent(database: &str, key: &str) -> Result<(String, String), Errno> {
    if database.is_empty() || key.is_empty() {
        return Err(Errno::new(-22));
    }
    Ok((database.to_string(), key.to_string()))
}

pub fn change_uid_gid_raw(
    uid: u32,
    gid: u32,
    supplementary_gids: &[u32],
) -> Result<UserIdentity, Errno> {
    Ok(UserIdentity {
        uid,
        gid,
        home: String::new(),
        supplementary_gids: supplementary_gids.to_vec(),
    })
}

pub fn change_uid_gid(
    user: Option<&str>,
    passwd_line: Option<&str>,
    initgroups_line: Option<&str>,
) -> Result<UserIdentity, Errno> {
    match user {
        None | Some("root") | Some("0") => return change_uid_gid_raw(0, 0, &[]),
        Some(_) => {}
    }

    let passwd = passwd_line.ok_or_else(|| Errno::new(-3))?;
    let mut fields = passwd.split(':');
    let _name = fields.next();
    let _password = fields.next();
    let uid = fields
        .next()
        .ok_or_else(|| Errno::new(-5))?
        .parse::<u32>()
        .map_err(|_| Errno::new(-5))?;
    let gid = fields
        .next()
        .ok_or_else(|| Errno::new(-5))?
        .parse::<u32>()
        .map_err(|_| Errno::new(-5))?;
    let _gecos = fields.next();
    let home = fields.next().ok_or_else(|| Errno::new(-5))?.to_string();

    let groups = initgroups_line
        .unwrap_or_default()
        .split_whitespace()
        .skip(1)
        .filter_map(|g| g.parse::<u32>().ok())
        .collect::<Vec<_>>();

    Ok(UserIdentity {
        uid,
        gid,
        home,
        supplementary_gids: groups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_shortcut_resets_to_zero_ids() {
        let identity = change_uid_gid(Some("root"), None, None).unwrap();
        assert_eq!((identity.uid, identity.gid), (0, 0));
    }

    #[test]
    fn passwd_and_initgroups_are_parsed() {
        let identity = change_uid_gid(
            Some("alice"),
            Some("alice:x:1000:100:Alice:/home/alice:/bin/bash"),
            Some("alice 100 200 300"),
        )
        .unwrap();
        assert_eq!(identity.uid, 1000);
        assert_eq!(identity.gid, 100);
        assert_eq!(identity.home, "/home/alice");
        assert_eq!(identity.supplementary_gids, vec![100, 200, 300]);
    }
}
