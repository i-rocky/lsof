use std::collections::HashSet;

use crate::error::Error;
use crate::model::{Action, NetFilter, Options, Protocol};

pub(crate) const USAGE: &str =
    "usage: lsof [-nP] [-t] [-p pid[,pid...]] [-i [tcp|udp][@host][:port]]";

pub(crate) const HELP_TEXT: &str =
    "usage: lsof [-nP] [-t] [-p pid[,pid...]] [-i [tcp|udp][@host][:port]]

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

pub(crate) fn parse_args(args: &[String]) -> Result<Action, Error> {
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

fn parse_proto_token(token: &str) -> Result<Protocol, Error> {
    match token.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        _ => Err(Error::Usage(format!(
            "invalid protocol in -i spec: '{token}'"
        ))),
    }
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
            filter.protocol = Some(parse_proto_token(proto_raw)?);
        }
        if !port_raw.is_empty() {
            filter.port = Some(parse_port_value(port_raw)?);
        }
        return Ok(());
    }

    filter.protocol = Some(parse_proto_token(segment)?);
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
}
