use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fmt;
use std::io;
use std::process::{self, Command};

const USAGE: &str = "usage: lsof [-nP] [-t] [-p pid[,pid...]] [-i [tcp|udp][@host][:port]]";
const HELP_TEXT: &str = "usage: lsof [-nP] [-t] [-p pid[,pid...]] [-i [tcp|udp][@host][:port]]

List open sockets in an lsof-style view on Windows.

Options:
 -i [spec]   select by socket spec; supports proto tcp/udp, host, and port
 -n          accepted for lsof compatibility (numeric hosts)
 -P          accepted for lsof compatibility (numeric ports)
 -p <pids>   filter by PID list (comma-separated)
 -t          terse mode (print PIDs only)
 -h, --help  display this help
 -v, --version
             display version

Examples:
 lsof -i
 lsof -i :3000
 lsof -i tcp:443
 lsof -i udp@127.0.0.1:53
 lsof -t -i :8080";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn from_token(token: &str) -> Result<Self, Error> {
        match token.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(Error::Usage(format!(
                "invalid protocol in -i spec: '{token}'"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NetFilter {
    protocol: Option<Protocol>,
    host: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Options {
    terse: bool,
    pid_filter: Option<HashSet<u32>>,
    net_filter: NetFilter,
    include_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Help,
    Version,
    List(Options),
}

#[derive(Debug)]
enum Error {
    Usage(String),
    Runtime(String),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) | Self::Runtime(msg) => write!(f, "{msg}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone)]
struct SocketEntry {
    protocol: Protocol,
    local_address: String,
    foreign_address: String,
    state: String,
    pid: u32,
}

#[derive(Debug, Clone)]
struct DisplayRow {
    command: String,
    pid: u32,
    protocol: Protocol,
    local_address: String,
    foreign_address: String,
    state: String,
}

fn main() {
    match run(env::args().collect()) {
        Ok(()) => process::exit(0),
        Err(Error::Usage(msg)) => {
            eprintln!("lsof: {msg}");
            eprintln!("{USAGE}");
            process::exit(1);
        }
        Err(err) => {
            eprintln!("lsof: {err}");
            process::exit(1);
        }
    }
}

fn run(args: Vec<String>) -> Result<(), Error> {
    match parse_args(&args[1..])? {
        Action::Help => {
            println!("{HELP_TEXT}");
            Ok(())
        }
        Action::Version => {
            println!("lsof {version}", version = env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Action::List(opts) => run_list(opts),
    }
}

fn parse_args(args: &[String]) -> Result<Action, Error> {
    let mut opts = Options::default();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        if arg == "-h" || arg == "--help" {
            return Ok(Action::Help);
        }
        if arg == "-v" || arg == "--version" {
            return Ok(Action::Version);
        }

        if arg == "-t" {
            opts.terse = true;
            i += 1;
            continue;
        }

        if arg == "-n" || arg == "-P" {
            i += 1;
            continue;
        }

        if arg == "-i" {
            opts.include_network = true;
            if let Some(value) = args.get(i + 1) {
                if !value.starts_with('-') {
                    opts.net_filter = parse_i_spec(value)?;
                    i += 1;
                }
            }
            i += 1;
            continue;
        }

        if let Some(spec) = arg.strip_prefix("-i") {
            opts.include_network = true;
            opts.net_filter = parse_i_spec(spec)?;
            i += 1;
            continue;
        }

        if arg == "-p" {
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| Error::Usage("-p requires a PID list".to_string()))?;
            opts.pid_filter = Some(parse_pid_list(value)?);
            i += 1;
            continue;
        }

        if let Some(value) = arg.strip_prefix("-p") {
            if value.is_empty() {
                return Err(Error::Usage("-p requires a PID list".to_string()));
            }
            opts.pid_filter = Some(parse_pid_list(value)?);
            i += 1;
            continue;
        }

        return Err(Error::Usage(format!("unsupported option: {arg}")));
    }

    if !opts.include_network {
        opts.include_network = true;
    }

    Ok(Action::List(opts))
}

fn parse_pid_list(raw: &str) -> Result<HashSet<u32>, Error> {
    let mut pids = HashSet::new();
    for part in raw.split(',') {
        let value = part.trim();
        if value.is_empty() {
            continue;
        }
        let pid = value
            .parse::<u32>()
            .map_err(|_| Error::Usage(format!("invalid pid in list: '{value}'")))?;
        pids.insert(pid);
    }

    if pids.is_empty() {
        return Err(Error::Usage("-p requires at least one PID".to_string()));
    }

    Ok(pids)
}

fn parse_i_spec(raw: &str) -> Result<NetFilter, Error> {
    let spec = raw.trim();
    if spec.is_empty() {
        return Ok(NetFilter::default());
    }

    let mut filter = NetFilter::default();

    if let Some((before_at, after_at)) = spec.split_once('@') {
        parse_proto_port_segment(before_at, &mut filter)?;
        parse_host_port_segment(after_at, &mut filter)?;
    } else {
        parse_proto_port_segment(spec, &mut filter)?;
    }

    Ok(filter)
}

fn parse_proto_port_segment(segment: &str, filter: &mut NetFilter) -> Result<(), Error> {
    if segment.is_empty() {
        return Ok(());
    }

    if let Some(port_raw) = segment.strip_prefix(':') {
        filter.port = Some(parse_port_value(port_raw)?);
        return Ok(());
    }

    if let Some((proto_raw, port_raw)) = segment.split_once(':') {
        if !proto_raw.is_empty() {
            filter.protocol = Some(Protocol::from_token(proto_raw)?);
        }
        if !port_raw.is_empty() {
            filter.port = Some(parse_port_value(port_raw)?);
        }
        return Ok(());
    }

    filter.protocol = Some(Protocol::from_token(segment)?);
    Ok(())
}

fn parse_host_port_segment(segment: &str, filter: &mut NetFilter) -> Result<(), Error> {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    if let Some((host_raw, port_raw)) = split_host_port(trimmed) {
        if !host_raw.is_empty() {
            filter.host = Some(host_raw.to_ascii_lowercase());
        }
        if filter.port.is_none() {
            filter.port = Some(parse_port_value(port_raw)?);
        }
    } else {
        filter.host = Some(trimmed.to_ascii_lowercase());
    }

    Ok(())
}

fn split_host_port(input: &str) -> Option<(&str, &str)> {
    let (left, right) = input.rsplit_once(':')?;
    if right.chars().all(|ch| ch.is_ascii_digit()) {
        return Some((left, right));
    }
    None
}

fn parse_port_value(raw: &str) -> Result<u16, Error> {
    raw.parse::<u16>()
        .map_err(|_| Error::Usage(format!("invalid port in -i spec: '{raw}'")))
}

fn run_list(opts: Options) -> Result<(), Error> {
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

    fn strings(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn parse_default_action_lists_network() {
        let action = parse_args(&[]).expect("parse should succeed");
        let Action::List(opts) = action else {
            panic!("expected list action");
        };

        assert!(opts.include_network);
        assert_eq!(opts.net_filter, NetFilter::default());
    }

    #[test]
    fn parse_i_short_with_attached_spec() {
        let action = parse_args(&strings(&["-itcp:443"])).expect("parse should succeed");
        let Action::List(opts) = action else {
            panic!("expected list action");
        };

        assert_eq!(opts.net_filter.protocol, Some(Protocol::Tcp));
        assert_eq!(opts.net_filter.port, Some(443));
    }

    #[test]
    fn parse_i_with_host_and_port() {
        let filter = parse_i_spec("udp@127.0.0.1:53").expect("spec should parse");
        assert_eq!(filter.protocol, Some(Protocol::Udp));
        assert_eq!(filter.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(filter.port, Some(53));
    }

    #[test]
    fn parse_i_with_port_only() {
        let filter = parse_i_spec(":3000").expect("spec should parse");
        assert_eq!(filter.protocol, None);
        assert_eq!(filter.host, None);
        assert_eq!(filter.port, Some(3000));
    }

    #[test]
    fn parse_pid_list_comma_separated() {
        let pids = parse_pid_list("1,22,333").expect("pid list should parse");
        assert!(pids.contains(&1));
        assert!(pids.contains(&22));
        assert!(pids.contains(&333));
    }

    #[test]
    fn parse_pid_list_rejects_invalid_value() {
        let err = parse_pid_list("10,abc").expect_err("pid list should fail");
        assert_eq!(err.to_string(), "invalid pid in list: 'abc'");
    }

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
