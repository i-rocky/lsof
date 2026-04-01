use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::model::{DisplayRow, FileOptions, FileUseRow, Options, ProcessInfo, SocketEntry};
use crate::windows::{collect_file_usage, collect_process_map, collect_socket_entries};

const NETWORK_HEADER: &str = "COMMAND                     PID PROTO LOCAL_ADDRESS                  FOREIGN_ADDRESS                STATE";
const FILE_HEADER: &str = "COMMAND                     PID PROCESS_PATH";

pub(crate) fn run_list(opts: Options) -> Result<(), Error> {
    let sockets = collect_socket_entries()?;
    let process_map = collect_process_map(sockets.iter().map(|socket| socket.pid));
    let rows = build_display_rows(sockets, &process_map, &opts);
    print!("{}", render_list_output(&rows, opts.terse));
    Ok(())
}

pub(crate) fn run_file(opts: FileOptions) -> Result<(), Error> {
    let resolved = resolve_file_path(&opts.path)?;
    let rows = collect_file_usage(&resolved)?;
    print!("{}", render_file_output(&rows));
    Ok(())
}

fn resolve_file_path(path: &Path) -> Result<PathBuf, Error> {
    fs::canonicalize(path).map_err(|err| {
        Error::Runtime(format!(
            "failed to resolve file path '{}': {err}",
            path.display()
        ))
    })
}

fn build_display_rows(
    sockets: Vec<SocketEntry>,
    process_map: &HashMap<u32, ProcessInfo>,
    opts: &Options,
) -> Vec<DisplayRow> {
    let mut rows = Vec::new();

    for socket in sockets {
        if !matches_socket_filter(&socket, opts) {
            continue;
        }

        let command = process_map
            .get(&socket.pid)
            .map(|process| process.command.clone())
            .unwrap_or_else(|| "<unknown>".to_string());

        rows.push(DisplayRow {
            command,
            pid: socket.pid,
            protocol: socket.protocol,
            local_address: socket.local_address,
            foreign_address: socket.foreign_address,
            state: socket.state,
        });
    }

    rows.sort_by(|a, b| {
        a.pid
            .cmp(&b.pid)
            .then(a.command.cmp(&b.command))
            .then(a.protocol.as_str().cmp(b.protocol.as_str()))
            .then(a.local_address.cmp(&b.local_address))
            .then(a.foreign_address.cmp(&b.foreign_address))
    });

    rows
}

fn render_list_output(rows: &[DisplayRow], terse: bool) -> String {
    if terse {
        return render_terse_output(rows);
    }

    let mut out = String::new();
    out.push_str(NETWORK_HEADER);
    out.push('\n');

    for row in rows {
        out.push_str(&format!(
            "{:<24} {:>6} {:<5} {:<30} {:<30} {}\n",
            truncate_display(&row.command, 24),
            row.pid,
            row.protocol.as_str(),
            truncate_display(&row.local_address, 30),
            truncate_display(&row.foreign_address, 30),
            row.state
        ));
    }

    out
}

fn render_terse_output(rows: &[DisplayRow]) -> String {
    let mut pids = BTreeSet::new();
    for row in rows {
        pids.insert(row.pid);
    }

    let mut out = String::new();
    for pid in pids {
        out.push_str(&format!("{pid}\n"));
    }
    out
}

fn render_file_output(rows: &[FileUseRow]) -> String {
    let mut out = String::new();
    out.push_str(FILE_HEADER);
    out.push('\n');

    for row in rows {
        out.push_str(&format!(
            "{:<24} {:>6} {}\n",
            truncate_display(&row.command, 24),
            row.pid,
            row.process_path
        ));
    }

    out
}

fn truncate_display(value: &str, width: usize) -> String {
    let mut out = String::new();
    for ch in value.chars().take(width) {
        out.push(ch);
    }
    out
}

fn matches_socket_filter(socket: &SocketEntry, opts: &Options) -> bool {
    if let Some(protocol) = opts.net_filter.protocol {
        if socket.protocol != protocol {
            return false;
        }
    }

    if let Some(pid_filter) = &opts.pid_filter {
        if !pid_filter.contains(&socket.pid) {
            return false;
        }
    }

    if let Some(port) = opts.net_filter.port {
        let local_port = extract_port(&socket.local_address);
        let foreign_port = extract_port(&socket.foreign_address);

        if local_port != Some(port) && foreign_port != Some(port) {
            return false;
        }
    }

    if let Some(host) = &opts.net_filter.host {
        let local = socket.local_address.to_ascii_lowercase();
        let foreign = socket.foreign_address.to_ascii_lowercase();

        if !local.contains(host) && !foreign.contains(host) {
            return false;
        }
    }

    true
}

fn extract_port(endpoint: &str) -> Option<u16> {
    let value = endpoint.trim();
    if value == "*:*" {
        return None;
    }

    let (_, port) = value.rsplit_once(':')?;
    port.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    use crate::model::{NetFilter, Options, ProcessInfo, Protocol, SocketEntry};

    use super::*;

    fn sample_socket(
        pid: u32,
        protocol: Protocol,
        local_address: &str,
        foreign_address: &str,
        state: &str,
    ) -> SocketEntry {
        SocketEntry {
            protocol,
            local_address: local_address.to_string(),
            foreign_address: foreign_address.to_string(),
            state: state.to_string(),
            pid,
        }
    }

    #[test]
    fn filter_matches_port_on_local_or_foreign_endpoint() {
        let socket = sample_socket(
            555,
            Protocol::Tcp,
            "127.0.0.1:65123",
            "127.0.0.1:3000",
            "ESTABLISHED",
        );

        let opts = Options {
            net_filter: NetFilter {
                protocol: Some(Protocol::Tcp),
                host: None,
                port: Some(3000),
            },
            ..Options::default()
        };

        assert!(matches_socket_filter(&socket, &opts));
    }

    #[test]
    fn filter_rejects_pid_mismatch() {
        let socket = sample_socket(222, Protocol::Tcp, "127.0.0.1:8080", "0.0.0.0:0", "LISTEN");
        let opts = Options {
            pid_filter: Some(HashSet::from([111])),
            ..Options::default()
        };

        assert!(!matches_socket_filter(&socket, &opts));
    }

    #[test]
    fn filter_matches_host_on_foreign_endpoint() {
        let socket = sample_socket(
            555,
            Protocol::Tcp,
            "10.0.0.5:65123",
            "127.0.0.1:3000",
            "ESTABLISHED",
        );
        let opts = Options {
            net_filter: NetFilter {
                protocol: None,
                host: Some("127.0.0.1".to_string()),
                port: None,
            },
            ..Options::default()
        };

        assert!(matches_socket_filter(&socket, &opts));
    }

    #[test]
    fn filter_rejects_protocol_mismatch() {
        let socket = sample_socket(555, Protocol::Udp, "127.0.0.1:5353", "*:*", "");
        let opts = Options {
            net_filter: NetFilter {
                protocol: Some(Protocol::Tcp),
                host: None,
                port: None,
            },
            ..Options::default()
        };

        assert!(!matches_socket_filter(&socket, &opts));
    }

    #[test]
    fn extract_port_handles_ipv6_endpoint() {
        assert_eq!(extract_port("[::1]:8080"), Some(8080));
        assert_eq!(extract_port("*:*"), None);
    }

    #[test]
    fn extract_port_handles_scoped_ipv6_endpoint() {
        assert_eq!(extract_port("[fe80::1%4]:5353"), Some(5353));
    }

    #[test]
    fn build_display_rows_sorts_and_uses_unknown_command_fallback() {
        let sockets = vec![
            sample_socket(20, Protocol::Tcp, "127.0.0.1:8080", "0.0.0.0:0", "LISTEN"),
            sample_socket(10, Protocol::Udp, "127.0.0.1:5353", "*:*", ""),
        ];
        let mut process_map = HashMap::new();
        process_map.insert(
            10,
            ProcessInfo {
                command: "proc.exe".to_string(),
                process_path: "C:\\proc.exe".to_string(),
            },
        );

        let rows = build_display_rows(sockets, &process_map, &Options::default());

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pid, 10);
        assert_eq!(rows[0].command, "proc.exe");
        assert_eq!(rows[1].pid, 20);
        assert_eq!(rows[1].command, "<unknown>");
    }

    #[test]
    fn render_terse_output_deduplicates_and_sorts_pids() {
        let rows = vec![
            DisplayRow {
                command: "a.exe".to_string(),
                pid: 20,
                protocol: Protocol::Tcp,
                local_address: "127.0.0.1:1".to_string(),
                foreign_address: "0.0.0.0:0".to_string(),
                state: "LISTEN".to_string(),
            },
            DisplayRow {
                command: "b.exe".to_string(),
                pid: 10,
                protocol: Protocol::Tcp,
                local_address: "127.0.0.1:2".to_string(),
                foreign_address: "0.0.0.0:0".to_string(),
                state: "LISTEN".to_string(),
            },
            DisplayRow {
                command: "c.exe".to_string(),
                pid: 20,
                protocol: Protocol::Udp,
                local_address: "127.0.0.1:3".to_string(),
                foreign_address: "*:*".to_string(),
                state: String::new(),
            },
        ];

        assert_eq!(render_list_output(&rows, true), "10\n20\n");
    }

    #[test]
    fn render_list_output_keeps_exact_header_contract() {
        let output = render_list_output(&[], false);
        assert_eq!(output, format!("{NETWORK_HEADER}\n"));
    }

    #[test]
    fn render_file_output_keeps_exact_header_contract() {
        let output = render_file_output(&[]);
        assert_eq!(output, format!("{FILE_HEADER}\n"));
    }

    #[test]
    fn resolve_file_path_returns_useful_error_for_missing_path() {
        let path = PathBuf::from("__missing__\\definitely-not-here.txt");
        let err = resolve_file_path(&path).expect_err("path should fail");
        assert_eq!(
            err.to_string(),
            format!(
                "failed to resolve file path '{}': The system cannot find the path specified. (os error 3)",
                path.display()
            )
        );
    }
}
