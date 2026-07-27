#!/usr/bin/env python3
"""Keep Rust credential plaintext inside pinned, bounded, zeroizing owners."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CREDS = ROOT / "src/shared/rust/creds_util.rs"
MACHINE = ROOT / "src/shared/rust/machine_credential.rs"
SECRET = ROOT / "src/shared/rust/secret_bytes.rs"
C_CREDS = ROOT / "src/shared/creds-util.c"
C_MACHINE = ROOT / "src/shared/machine-credential.c"


def require(text: str, fragments: tuple[str, ...], label: str) -> list[str]:
    return [f"{label}: missing {fragment!r}" for fragment in fragments if fragment not in text]


def main() -> int:
    creds = CREDS.read_text(encoding="utf-8")
    machine = MACHINE.read_text(encoding="utf-8")
    secret = SECRET.read_text(encoding="utf-8")
    c_creds = C_CREDS.read_text(encoding="utf-8")
    c_machine = C_MACHINE.read_text(encoding="utf-8")
    machine_production = machine.split("#[cfg(test)]", 1)[0]
    errors: list[str] = []

    errors += require(
        creds,
        (
            "pub struct CredentialsDir",
            "directory: File",
            "path: PathBuf",
            "libc::openat(",
            "self.directory.as_raw_fd()",
            "libc::O_RDONLY | libc::O_CLOEXEC",
            "let mut nul_terminated = [0_u8; CREDENTIAL_NAME_MAX + 1]",
            "fn read_secret_bounded(",
            ".checked_add(1)",
            "SecretBytes::try_zeroed(capacity)",
            "io::ErrorKind::Interrupted",
            "length as u64 > maximum_size",
            "data.finalize_prefix(length)",
            "error.raw_os_error() == Some(libc::ENXIO)",
            "UnixStream::connect(path)",
            "socket.shutdown(Shutdown::Write)",
            "CredentialsDir::open()?.read_name(name)",
        ),
        str(CREDS.relative_to(ROOT)),
    )
    errors += require(
        machine_production,
        (
            "try_cunescape_into(",
            "UnescapeFlags::ACCEPT_NUL",
            "SecretBytes::try_zeroed(s.len())",
            "error == Errno::ENOMEM.to_neg_errno()",
            "MachineCredentialError::OutOfMemory",
            "SecretBytesFinalizeError::OutOfMemory => Errno::ENOMEM.to_neg_errno()",
            "read_credential_path(path, true)",
            "CredentialsDir::open_path(directory_path)",
            ".read_name(source)",
            "self.insert_owned(id, data)",
        ),
        str(MACHINE.relative_to(ROOT)),
    )
    errors += require(
        secret,
        (
            "pub struct SecretBytes(Vec<u8>)",
            "libc::explicit_bzero(",
            "self.0.capacity()",
            'field("contents", &"<redacted>")',
        ),
        str(SECRET.relative_to(ROOT)),
    )
    errors += require(
        c_creds,
        (
            "open(d, O_CLOEXEC|O_DIRECTORY)",
            "READ_FULL_FILE_SECURE",
        ),
        str(C_CREDS.relative_to(ROOT)),
    )
    errors += require(
        c_machine,
        (
            "UNESCAPE_ACCEPT_NUL",
            "READ_FULL_FILE_SECURE",
            "READ_FULL_FILE_CONNECT_SOCKET",
        ),
        str(C_MACHINE.relative_to(ROOT)),
    )

    for forbidden in (
        "std::fs::read(",
        "SecretBytes::from_vec(data)",
        "fn hex_val(",
        "fn resolve_credential_path(",
    ):
        if forbidden in machine_production:
            errors.append(
                f"{MACHINE.relative_to(ROOT)}: forbidden plaintext/path duplicate {forbidden!r}"
            )

    if "impl Clone for SecretBytes" in secret or "#[derive(Clone" in secret:
        errors.append(f"{SECRET.relative_to(ROOT)}: SecretBytes must remain non-Clone")

    if errors:
        print("Credential safety architecture gate FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    print(
        "Credential safety architecture OK: "
        "directory=openat bounded=1MiB socket=ENXIO-fallback "
        "plaintext=SecretBytes unescape=canonical"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
