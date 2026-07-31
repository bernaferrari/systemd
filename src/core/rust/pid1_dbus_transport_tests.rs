// SPDX-License-Identifier: LGPL-2.1-or-later

//! Focused tests for connection-local private-bus protocol handling.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::unistd::geteuid;
use systemd_event_loop_rs::loop_::EventLoop;

use super::*;
use crate::pid1_bus_source::pid1_bus_command_channel;
use crate::pid1_dbus_command_adapter::Pid1DbusCommandAdapter;
use crate::pid1_dbus_event_source::PrivateBusDispatchOutcome;
use crate::pid1_dbus_listener::PrivateBusListener;
use crate::pid1_dbus_reply_queue::PrivateBusReplyTracking;
use crate::pid1_dbus_transport_types::PrivateBusWireDispatchOutcome;
use crate::pid1_manager_commands::{Pid1ManagerCommand, SenderIdentity};

fn socket_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "systemd-rust-private-bus-transport-{name}-{}-{stamp}.socket",
        std::process::id()
    ))
}

fn owner(
    event_loop: &mut EventLoop,
    name: &str,
    limit: usize,
) -> (PathBuf, PrivateBusTransportOwner) {
    let path = socket_path(name);
    let listener = UnixListener::bind(&path).unwrap();
    let listener = PrivateBusListener::from_bound_listener(listener, geteuid().as_raw()).unwrap();
    let owner =
        PrivateBusTransportOwner::register(event_loop, listener, NonZeroUsize::new(limit).unwrap())
            .unwrap();
    (path, owner)
}

fn dispatch(
    owner: &mut PrivateBusTransportOwner,
    event_loop: &mut EventLoop,
) -> PrivateBusDispatchOutcome {
    owner
        .dispatch_ready(
            event_loop,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            || Ok([0x5a; 16]),
        )
        .unwrap()
}

fn wire_slot_config(input_capacity: usize) -> PrivateBusWireSlotConfig {
    PrivateBusWireSlotConfig::new(input_capacity, NonZeroUsize::new(2).unwrap(), 2048, 2048)
}

fn push_padding(bytes: &mut Vec<u8>, alignment: usize) {
    let padding = (alignment - bytes.len() % alignment) % alignment;
    bytes.resize(bytes.len() + padding, 0);
}

fn push_text(bytes: &mut Vec<u8>, value: &str, signature: bool) {
    if signature {
        bytes.push(u8::try_from(value.len()).unwrap());
    } else {
        push_padding(bytes, 4);
        bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    }
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
}

fn push_header(fields: &mut Vec<u8>, code: u8, kind: u8, value: &str) {
    push_padding(fields, 8);
    fields.extend_from_slice(&[code, 1, kind, 0]);
    push_text(fields, value, kind == b'g');
}

fn peer_ping_call(serial: u32) -> Vec<u8> {
    let mut fields = Vec::new();
    push_header(&mut fields, 1, b'o', "/org/freedesktop/systemd1");
    push_header(&mut fields, 2, b's', "org.freedesktop.DBus.Peer");
    push_header(&mut fields, 3, b's', "Ping");
    let mut output = vec![b'l', 1, 0, 1, 0, 0, 0, 0];
    output.extend_from_slice(&serial.to_le_bytes());
    output.extend_from_slice(&u32::try_from(fields.len()).unwrap().to_le_bytes());
    output.extend_from_slice(&fields);
    push_padding(&mut output, 8);
    output
}

fn peer_get_machine_id_call(serial: u32) -> Vec<u8> {
    let mut fields = Vec::new();
    push_header(&mut fields, 1, b'o', "/org/freedesktop/systemd1");
    push_header(&mut fields, 2, b's', "org.freedesktop.DBus.Peer");
    push_header(&mut fields, 3, b's', "GetMachineId");
    let mut output = vec![b'l', 1, 0, 1, 0, 0, 0, 0];
    output.extend_from_slice(&serial.to_le_bytes());
    output.extend_from_slice(&u32::try_from(fields.len()).unwrap().to_le_bytes());
    output.extend_from_slice(&fields);
    push_padding(&mut output, 8);
    output
}

fn little_endian_text_reply_body(frame: &[u8]) -> &[u8] {
    assert_eq!(frame[0], b'l');
    assert_eq!(frame[1], 2);
    let header_length =
        usize::try_from(u32::from_le_bytes(frame[12..16].try_into().unwrap())).unwrap();
    let header_end = 16 + header_length;
    let body_offset = (header_end + 7) & !7;
    let length = usize::try_from(u32::from_le_bytes(
        frame[body_offset..body_offset + 4].try_into().unwrap(),
    ))
    .unwrap();
    assert_eq!(frame[body_offset + 4 + length], 0);
    &frame[body_offset + 4..body_offset + 4 + length]
}

fn external_token() -> Vec<u8> {
    geteuid()
        .as_raw()
        .to_string()
        .bytes()
        .flat_map(|byte| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0xf)]]
        })
        .collect()
}

fn authenticate_to_handoff_with_initial(
    owner: &mut PrivateBusTransportOwner,
    event_loop: &mut EventLoop,
    client: &mut UnixStream,
    initial_wire_bytes: &[u8],
) {
    event_loop.run_once(0).unwrap();
    assert_eq!(dispatch(owner, event_loop).accepted, 1);

    client.write_all(b"\0AUTH EXTERNAL\r\n").unwrap();
    event_loop.run_once(0).unwrap();
    dispatch(owner, event_loop);
    event_loop.run_once(0).unwrap();
    dispatch(owner, event_loop);
    let mut challenge = [0_u8; 6];
    client.read_exact(&mut challenge).unwrap();
    assert_eq!(&challenge, b"DATA\r\n");

    let mut response = b"DATA ".to_vec();
    response.extend_from_slice(&external_token());
    response.extend_from_slice(b"\r\nBEGIN\r\n");
    response.extend_from_slice(initial_wire_bytes);
    client.write_all(&response).unwrap();
    event_loop.run_once(0).unwrap();
    dispatch(owner, event_loop);
    event_loop.run_once(0).unwrap();
    assert_eq!(dispatch(owner, event_loop).authenticated, 1);
}

#[test]
fn peer_ping_replies_locally_without_consuming_manager_inbox_capacity() {
    let call = peer_ping_call(29);
    let mut event_loop = EventLoop::new().unwrap();
    let (path, mut owner) = owner(&mut event_loop, "peer-ping", 1);
    let mut client = UnixStream::connect(&path).unwrap();
    authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
    let wire_id = owner
        .promote_authenticated_to_wire(wire_slot_config(call.len()))
        .unwrap()
        .unwrap();
    let sender_identity = SenderIdentity::from_authenticated_peer(
        owner.wire_slot(wire_id).unwrap().connection().peer(),
    );
    let (command_sender, _inbox) = pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
    let adapter = Pid1DbusCommandAdapter::new(command_sender.clone());

    assert_eq!(
        owner.dispatch_wire_slot_once(wire_id, &adapter),
        Ok(PrivateBusWireDispatchOutcome::HandledLocally {
            reply: PrivateBusReplyTracking::Queued,
        })
    );
    let slot = owner.wire_slot(wire_id).unwrap();
    assert_eq!(slot.replies().pending_reply_count(), 0);
    let frame = slot.current_reply_frame().unwrap();
    assert_eq!(frame[0], b'l');
    assert_eq!(frame[1], 2);
    assert_eq!(u32::from_le_bytes(frame[4..8].try_into().unwrap()), 0);
    assert!(
        frame
            .windows(4)
            .any(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) == 29)
    );

    assert!(
        command_sender
            .try_send(
                sender_identity,
                Pid1ManagerCommand::LoadUnit {
                    name: "still-available.service".into(),
                },
            )
            .is_ok()
    );

    owner.unregister(&mut event_loop).unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn peer_get_machine_id_replies_locally_without_consuming_manager_inbox_capacity() {
    let call = peer_get_machine_id_call(31);
    let mut event_loop = EventLoop::new().unwrap();
    let (path, mut owner) = owner(&mut event_loop, "peer-machine-id", 1);
    let mut client = UnixStream::connect(&path).unwrap();
    authenticate_to_handoff_with_initial(&mut owner, &mut event_loop, &mut client, &call);
    let wire_id = owner
        .promote_authenticated_to_wire(wire_slot_config(call.len()))
        .unwrap()
        .unwrap();
    let sender_identity = SenderIdentity::from_authenticated_peer(
        owner.wire_slot(wire_id).unwrap().connection().peer(),
    );
    let (command_sender, _inbox) = pid1_bus_command_channel(NonZeroUsize::new(1).unwrap()).unwrap();
    let adapter = Pid1DbusCommandAdapter::new(command_sender.clone());

    match owner.dispatch_wire_slot_once(wire_id, &adapter) {
        Ok(PrivateBusWireDispatchOutcome::HandledLocally {
            reply: PrivateBusReplyTracking::Queued,
        }) => {
            let frame = owner
                .wire_slot(wire_id)
                .unwrap()
                .current_reply_frame()
                .unwrap();
            assert_eq!(frame[1], 2);
            assert!(
                frame
                    .windows(b"org.freedesktop.systemd1".len())
                    .any(|window| window == b"org.freedesktop.systemd1")
            );
            let machine_id = little_endian_text_reply_body(frame);
            assert_eq!(machine_id.len(), 32);
            assert!(machine_id.iter().all(|byte| byte.is_ascii_hexdigit()));
        }
        Ok(PrivateBusWireDispatchOutcome::RejectedWithError {
            error: crate::pid1_dbus_reply_adapter::Pid1DbusProtocolError::Failed,
        }) => {
            // C's built-in Peer.GetMachineId is fallible as well. A missing
            // or invalid host machine ID must receive a correlated local
            // failure before any manager command is accepted.
            assert!(
                owner
                    .wire_slot(wire_id)
                    .unwrap()
                    .replies()
                    .current_frame()
                    .is_some()
            );
        }
        outcome => panic!("unexpected GetMachineId dispatch outcome: {outcome:?}"),
    }

    assert!(
        command_sender
            .try_send(
                sender_identity,
                Pid1ManagerCommand::LoadUnit {
                    name: "still-available.service".into(),
                },
            )
            .is_ok()
    );

    owner.unregister(&mut event_loop).unwrap();
    std::fs::remove_file(path).unwrap();
}
