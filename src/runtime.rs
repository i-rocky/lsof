use std::collections::{BTreeSet, HashMap};
use std::process::Command;

use crate::error::Error;
use crate::model::{DisplayRow, NetFilter, Options, Protocol, SocketEntry};

pub(crate) fn run_list(opts: Options) -> Result<(), Error> {
    if !cfg!(target_os = "windows") {
        return Err(Error::Runtime(
            "this implementation currently supports Windows runtime only".to_string(),
        ));
    }

    let process_map = collect_process_map()?;
    let sockets = collect_socket_entries()?;

    let mut rows = Vec::new();

    for socket in sockets {
        if !matches_socket_filter(&socket, &opts.net_filter) {
            continue;
        }

        if let Some(pid_filter) = &opts.pid_filter {
            if !pid_filter.contains(&socket.pid) {
                continue;
            }
        }

        let command = process_map
            .get(&socket.pid)
            .cloned()
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

    if opts.terse {
        let mut pids = BTreeSet::new();
        for row in rows {
            pids.insert(row.pid);
        }
        for pid in pids {
            println!("{pid}");
        }
        return Ok(());
    }

    println!(
        "{:<24} {:>6} {:<5} {:<30} {:<30} {}",
        "COMMAND", "PID", "PROTO", "LOCAL_ADDRESS", "FOREIGN_ADDRESS", "STATE"
    );

    for row in rows {
        println!(
            "{:<24} {:>6} {:<5} {:<30} {:<30} {}",
            truncate_display(&row.command, 24),
            row.pid,
            row.protocol.as_str(),
            truncate_display(&row.local_address, 30),
            truncate_display(&row.foreign_address, 30),
            row.state
        );
    }

    Ok(())
}

fn truncate_display(value: &str, width: usize) -> String {
    let mut out = String::new();
    for ch in value.chars().take(width) {
        out.push(ch);
    }
    out
}

fn matches_socket_filter(socket: &SocketEntry, filter: &NetFilter) -> bool {
    if let Some(protocol) = filter.protocol {
        if socket.protocol != protocol {
            return false;
        }
    }

    if let Some(port) = filter.port {
        let local_port = extract_port(&socket.local_address);
        let foreign_port = extract_port(&socket.foreign_address);

        if local_port != Some(port) && foreign_port != Some(port) {
            return false;
        }
    }

    if let Some(host) = &filter.host {
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

fn collect_socket_entries() -> Result<Vec<SocketEntry>, Error> {
    let mut entries = Vec::new();
    entries.extend(run_netstat_for("tcp", Protocol::Tcp)?);
    entries.extend(run_netstat_for("udp", Protocol::Udp)?);
    Ok(entries)
}

fn run_netstat_for(protocol_arg: &str, expected: Protocol) -> Result<Vec<SocketEntry>, Error> {
    let output = Command::new("netstat")
        .args(["-ano", "-p", protocol_arg])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Runtime(format!(
            "netstat failed for {protocol_arg}: {}",
            stderr.trim()
        )));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_netstat_output(&text, expected))
}

fn parse_netstat_output(text: &str, expected: Protocol) -> Vec<SocketEntry> {
    let mut rows = Vec::new();
    for line in text.lines() {
        if let Some(row) = parse_netstat_line(line, expected) {
            rows.push(row);
        }
    }
    rows
}

fn parse_netstat_line(line: &str, expected: Protocol) -> Option<SocketEntry> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return None;
    }

    let cols: Vec<&str> = trimmed.split_whitespace().collect();
    if cols.is_empty() {
        return None;
    }

    match cols[0].to_ascii_uppercase().as_str() {
        "TCP" if expected == Protocol::Tcp => {
            if cols.len() < 5 {
                return None;
            }
            let pid = cols[4].parse::<u32>().ok()?;
            Some(SocketEntry {
                protocol: Protocol::Tcp,
                local_address: cols[1].to_string(),
                foreign_address: cols[2].to_string(),
                state: cols[3].to_string(),
                pid,
            })
        }
        "UDP" if expected == Protocol::Udp => {
            if cols.len() < 4 {
                return None;
            }

            let (state, pid_col) = if cols.len() >= 5 {
                (cols[3].to_string(), cols[4])
            } else {
                (String::new(), cols[3])
            };

            let pid = pid_col.parse::<u32>().ok()?;
            Some(SocketEntry {
                protocol: Protocol::Udp,
                local_address: cols[1].to_string(),
                foreign_address: cols[2].to_string(),
                state,
                pid,
            })
        }
        _ => None,
    }
}

fn collect_process_map() -> Result<HashMap<u32, String>, Error> {
    let output = Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Runtime(format!(
            "tasklist failed: {}",
            stderr.trim()
        )));
    }

    let csv_text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_tasklist_csv(&csv_text))
}

fn parse_tasklist_csv(csv_text: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(csv_text.as_bytes());

    for row in reader.records().flatten() {
        if row.len() < 2 {
            continue;
        }

        let name = row.get(0).unwrap_or_default().trim().to_string();
        let pid_raw = row.get(1).unwrap_or_default().trim().replace(',', "");

        if let Ok(pid) = pid_raw.parse::<u32>() {
            map.insert(pid, name);
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_line_from_netstat() {
        let line = "  TCP    127.0.0.1:3000     0.0.0.0:0      LISTENING       4242";
        let row = parse_netstat_line(line, Protocol::Tcp).expect("line should parse");

        assert_eq!(row.protocol, Protocol::Tcp);
        assert_eq!(row.local_address, "127.0.0.1:3000");
        assert_eq!(row.foreign_address, "0.0.0.0:0");
        assert_eq!(row.state, "LISTENING");
        assert_eq!(row.pid, 4242);
    }

    #[test]
    fn parse_udp_line_from_netstat() {
        let line = "  UDP    0.0.0.0:5353       *:*                            912";
        let row = parse_netstat_line(line, Protocol::Udp).expect("line should parse");

        assert_eq!(row.protocol, Protocol::Udp);
        assert_eq!(row.local_address, "0.0.0.0:5353");
        assert_eq!(row.foreign_address, "*:*");
        assert_eq!(row.state, "");
        assert_eq!(row.pid, 912);
    }

    #[test]
    fn parse_tasklist_csv_rows() {
        let csv_text = "\"chrome.exe\",\"1234\",\"Console\",\"1\",\"123,456 K\"\n\"code.exe\",\"5678\",\"Console\",\"1\",\"456,789 K\"\n";
        let map = parse_tasklist_csv(csv_text);

        assert_eq!(map.get(&1234).map(String::as_str), Some("chrome.exe"));
        assert_eq!(map.get(&5678).map(String::as_str), Some("code.exe"));
    }

    #[test]
    fn filter_matches_port_on_local_or_foreign_endpoint() {
        let socket = SocketEntry {
            protocol: Protocol::Tcp,
            local_address: "127.0.0.1:65123".to_string(),
            foreign_address: "127.0.0.1:3000".to_string(),
            state: "ESTABLISHED".to_string(),
            pid: 555,
        };

        let filter = NetFilter {
            protocol: Some(Protocol::Tcp),
            host: None,
            port: Some(3000),
        };

        assert!(matches_socket_filter(&socket, &filter));
    }

    #[test]
    fn extract_port_handles_ipv6_endpoint() {
        assert_eq!(extract_port("[::1]:8080"), Some(8080));
        assert_eq!(extract_port("*:*"), None);
    }
}
