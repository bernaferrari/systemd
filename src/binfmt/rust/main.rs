// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/binfmt/binfmt.c

use std::{
    fs, io,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use systemd_binfmt_rs::{
    apply_rule_bytes, binfmt_mounted_and_writable, conf_paths, config_files_from_dirs,
    disable_binfmt, flush_binfmt, is_comment_or_empty_bytes, parse_binfmt_os_args,
    resolve_explicit_config_file, CatConfigMode, ParseBinfmtError,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const LONG_LINE_MAX: usize = 1024 * 1024;

#[derive(Default)]
struct ApplyReport {
    applied: usize,
    failed: usize,
}

impl ApplyReport {
    fn merge(&mut self, other: Self) {
        self.applied += other.applied;
        self.failed += other.failed;
    }
}

fn print_help() {
    println!("systemd-binfmt [OPTIONS...] [CONFIG...]");
    println!("Register binary formats with the kernel.");
    println!("  -h --help              Show this help");
    println!("     --version           Show this version");
    println!("     --unregister        Unregister all entries");
    println!("     --cat-config        Show configuration files");
    println!("     --tldr              Show brief configuration");
}

/// Apply every non-comment rule in a selected configuration file. Failure to
/// open an explicit file is deliberately returned to the caller; it is never
/// converted to a successful empty result.
fn apply_rules_from_file(path: &Path) -> io::Result<ApplyReport> {
    let mut input = BufReader::new(fs::File::open(path)?);
    let mut line = Vec::new();
    let mut report = ApplyReport::default();
    let mut line_number = 0;

    while read_bounded_line(&mut input, &mut line)? {
        line_number += 1;
        let rule = line.trim_ascii();
        if is_comment_or_empty_bytes(rule) {
            continue;
        }

        match apply_rule_bytes(rule) {
            Ok(()) => report.applied += 1,
            Err(error) => {
                eprintln!(
                    "binfmt: {}:{}: failed to apply rule: {error}",
                    path.display(),
                    line_number
                );
                report.failed += 1;
            }
        }
    }

    Ok(report)
}

fn read_bounded_line<R: BufRead>(input: &mut R, line: &mut Vec<u8>) -> io::Result<bool> {
    line.clear();
    let mut consumed = 0usize;
    let mut previous_eol = 0u8;

    loop {
        // Match read_line_full(): reaching the character limit is an error
        // even if EOF or an end-of-line marker would be observed next.
        if line.len() >= LONG_LINE_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "configuration line exceeds LONG_LINE_MAX (1 MiB)",
            ));
        }

        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok(consumed > 0);
        }

        let byte = available[0];
        let eol = match byte {
            0 => 0b001,
            b'\n' => 0b010,
            b'\r' => 0b100,
            _ => 0,
        };
        if previous_eol & 0b001 != 0
            || (eol == 0 && previous_eol != 0)
            || (eol != 0 && previous_eol & eol != 0)
        {
            return Ok(consumed > 0);
        }

        input.consume(1);
        consumed += 1;
        if eol == 0 {
            line.push(byte);
        } else {
            previous_eol |= eol;
        }
    }
}

fn apply_selected_files(files: &[PathBuf], ignore_enoent: bool) -> ApplyReport {
    let mut report = ApplyReport::default();

    for path in files {
        match apply_rules_from_file(path) {
            Ok(file_report) => report.merge(file_report),
            Err(error) if ignore_enoent && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                eprintln!("binfmt: failed to open {}: {error}", path.display());
                report.failed += 1;
            }
        }
    }

    report
}

fn check_binfmt_available() -> io::Result<bool> {
    match binfmt_mounted_and_writable()? {
        true => Ok(true),
        false => {
            eprintln!("binfmt: /proc/sys/fs/binfmt_misc is not mounted read-write, skipping");
            Ok(false)
        }
    }
}

fn cat_config(files: &[PathBuf], mode: CatConfigMode) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for (index, path) in files.iter().enumerate() {
        if index > 0 {
            writeln!(stdout)?;
        }
        writeln!(stdout, "# {}", path.display())?;

        let file = fs::File::open(path)?;
        if mode == CatConfigMode::On {
            io::copy(&mut BufReader::new(file), &mut stdout)?;
        } else {
            let mut input = BufReader::new(file);
            let mut line = Vec::new();
            while read_bounded_line(&mut input, &mut line)? {
                if is_comment_or_empty_bytes(&line) {
                    continue;
                }
                stdout.write_all(&line)?;
                writeln!(stdout)?;
            }
        }
    }

    Ok(())
}

fn run() -> io::Result<i32> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let binfmt_args = match parse_binfmt_os_args(&args) {
        Ok(args) => args,
        Err(ParseBinfmtError::HelpRequested) => {
            print_help();
            return Ok(0);
        }
        Err(ParseBinfmtError::VersionRequested) => {
            println!("systemd-binfmt {VERSION}");
            return Ok(0);
        }
        Err(ParseBinfmtError::InvalidArguments) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "argument parsing failed",
            ));
        }
    };

    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));

    if binfmt_args.unregister {
        disable_binfmt()?;
        return Ok(0);
    }

    if !binfmt_args.config_files.is_empty() {
        if !check_binfmt_available()? {
            return Ok(0);
        }

        let mut files = Vec::with_capacity(binfmt_args.config_files.len());
        let mut report = ApplyReport::default();
        for filename in &binfmt_args.config_files {
            // Matches apply_file(..., false): an absent explicit file is fatal.
            match resolve_explicit_config_file(filename) {
                Ok(path) => files.push(path),
                Err(error) => {
                    eprintln!("binfmt: failed to open {:?}: {error}", filename);
                    report.failed += 1;
                }
            }
        }
        report.merge(apply_selected_files(&files, false));
        eprintln!(
            "binfmt: {} rules applied, {} failed",
            report.applied, report.failed
        );
        return Ok((report.failed > 0) as i32);
    }

    let files = config_files_from_dirs(&conf_paths())?;
    if binfmt_args.cat_flags != CatConfigMode::Off {
        cat_config(&files, binfmt_args.cat_flags)?;
        return Ok(0);
    }

    if !check_binfmt_available()? {
        return Ok(0);
    }

    // The C implementation warns but continues if the startup flush fails.
    if let Err(error) = flush_binfmt() {
        eprintln!("binfmt: failed to flush binfmt_misc rules, ignoring: {error}");
    }

    let report = apply_selected_files(&files, true);
    eprintln!(
        "binfmt: {} rules applied, {} failed",
        report.applied, report.failed
    );
    Ok((report.failed > 0) as i32)
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("binfmt: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_accepts_final_line_without_newline() {
        let mut input = BufReader::new(&b":rule:M::"[..]);
        let mut line = Vec::new();

        assert!(read_bounded_line(&mut input, &mut line).unwrap());
        assert_eq!(line, b":rule:M::");
        assert!(!read_bounded_line(&mut input, &mut line).unwrap());
    }

    #[test]
    fn bounded_reader_rejects_overlong_configuration_line() {
        let content = vec![b'x'; LONG_LINE_MAX + 1];
        let mut input = BufReader::new(content.as_slice());
        let mut line = Vec::new();

        assert_eq!(
            read_bounded_line(&mut input, &mut line).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn bounded_reader_matches_c_end_of_line_combinations() {
        let mut input = BufReader::new(&b"one\r\ntwo\n\rthree\0four"[..]);
        let mut line = Vec::new();

        for expected in [b"one".as_slice(), b"two", b"three", b"four"] {
            assert!(read_bounded_line(&mut input, &mut line).unwrap());
            assert_eq!(line, expected);
        }
        assert!(!read_bounded_line(&mut input, &mut line).unwrap());
    }
}
