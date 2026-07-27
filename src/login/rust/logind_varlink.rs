// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/login/logind-varlink.c

use crate::logind_seat::Seat;
use crate::logind_session::Session;
use crate::logind_user::User;

pub fn get_user_by_uid(users: &[User], uid: u32) -> Result<String, String> {
    let user = users
        .iter()
        .find(|user| user.uid == uid)
        .ok_or_else(|| format!("no such user: {uid}"))?;
    Ok(format!(
        r#"{{"uid":{},"userName":"{}","state":"{}"}}"#,
        user.uid,
        user.user_name,
        user.state.as_str()
    ))
}

pub fn get_seat_by_name(seats: &[Seat], name: &str) -> Result<String, String> {
    let seat = seats
        .iter()
        .find(|seat| seat.id == name)
        .ok_or_else(|| format!("no such seat: {name}"))?;
    Ok(format!(
        r#"{{"name":"{}","state":"{}"}}"#,
        seat.id,
        seat.state.as_str()
    ))
}

pub fn get_session_by_id(sessions: &[Session], id: &str) -> Result<String, String> {
    let session = sessions
        .iter()
        .find(|session| session.id == id)
        .ok_or_else(|| format!("no such session: {id}"))?;
    Ok(format!(
        r#"{{"id":"{}","user":"{}","state":"{}"}}"#,
        session.id,
        session.user_name,
        session.state.as_str()
    ))
}
