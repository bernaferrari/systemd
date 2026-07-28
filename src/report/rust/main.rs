// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-report
//
// PORT-SYNC: src/report/report.c

use systemd_report_rs::{Action, Metric, metrics_name_valid, sort_metrics, validate_metric_batch};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-report [OPTIONS...] [METRIC...]");
    println!();
    println!("  -h --help             Show this help");
    println!("     --version          Show package version");
    println!("     --list             List available metrics");
    println!("     --describe         Describe metrics");
    println!("     --json             Output as JSON");
    println!("     --no-legend        Suppress legend");
}

fn print_version() {
    println!("systemd-report {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut action = Action::List;
    let mut json_output = false;
    let mut no_legend = false;
    let mut metric_names: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            "--list" => action = Action::List,
            "--describe" => action = Action::Describe,
            "--json" => json_output = true,
            "--no-legend" => no_legend = true,
            s if s.starts_with('-') => {
                eprintln!("report: unknown option: {}", s);
                std::process::exit(1);
            }
            other => metric_names.push(other.to_string()),
        }
        i += 1;
    }

    let report_dir = "/run/systemd/report";
    if !std::path::Path::new(report_dir).exists() {
        eprintln!("report: no report sources found ({})", report_dir);
        std::process::exit(0);
    }

    let mut sources: Vec<(String, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(report_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            if let Ok(target) = std::fs::read_link(&path) {
                sources.push((name, target.to_string_lossy().to_string()));
            } else {
                sources.push((name.clone(), path.to_string_lossy().to_string()));
            }
        }
    }
    sources.sort_by(|a, b| a.0.cmp(&b.0));

    match action {
        Action::List => {
            let mut metrics: Vec<Metric> = Vec::new();
            for (source_name, _addr) in &sources {
                if metric_names.is_empty()
                    || metric_names
                        .iter()
                        .any(|m| metrics_name_valid(m) && m.starts_with(source_name))
                {
                    let source_dir = format!("{}/{}", report_dir, source_name);
                    if let Ok(entries) = std::fs::read_dir(&source_dir) {
                        for entry in entries.flatten() {
                            let metric_file = entry.file_name().to_string_lossy().to_string();
                            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                                let parts: Vec<&str> = content.trim().splitn(3, ' ').collect();
                                let name = if metrics_name_valid(&metric_file) {
                                    metric_file.clone()
                                } else {
                                    format!("io.systemd.Report.{}", metric_file)
                                };
                                metrics.push(Metric {
                                    name,
                                    object: parts.get(0).map(|s| (*s).to_string()),
                                    fields: parts.get(1).map(|s| (*s).to_string()),
                                });
                            }
                        }
                    }
                }
            }

            if let Err(e) = validate_metric_batch(&metrics) {
                eprintln!("report: invalid metrics: {}", e);
                std::process::exit(1);
            }
            sort_metrics(&mut metrics);

            if json_output {
                println!("[");
                for (idx, m) in metrics.iter().enumerate() {
                    let comma = if idx + 1 < metrics.len() { "," } else { "" };
                    println!(
                        "  {{\"name\":\"{}\",\"object\":{},\"fields\":{}}}{}",
                        m.name,
                        m.object
                            .as_deref()
                            .map(|s| format!("\"{}\"", s))
                            .unwrap_or("null".to_string()),
                        m.fields
                            .as_deref()
                            .map(|s| format!("\"{}\"", s))
                            .unwrap_or("null".to_string()),
                        comma
                    );
                }
                println!("]");
            } else {
                if !no_legend {
                    println!("{:<50} {:<20} {}", "METRIC", "OBJECT", "FIELDS");
                }
                for m in &metrics {
                    println!(
                        "{:<50} {:<20} {}",
                        m.name,
                        m.object.as_deref().unwrap_or("-"),
                        m.fields.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        Action::Describe => {
            for (source_name, addr) in &sources {
                if json_output {
                    println!(
                        "{{\"source\":\"{}\",\"address\":\"{}\"}}",
                        source_name, addr
                    );
                } else {
                    println!("{}\t{}", source_name, addr);
                }
            }
        }
    }
}
