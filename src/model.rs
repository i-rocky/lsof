use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NetFilter {
    pub(crate) protocol: Option<Protocol>,
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Options {
    pub(crate) terse: bool,
    pub(crate) pid_filter: Option<HashSet<u32>>,
    pub(crate) net_filter: NetFilter,
    pub(crate) include_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Help,
    Version,
    List(Options),
}

#[derive(Debug, Clone)]
pub(crate) struct SocketEntry {
    pub(crate) protocol: Protocol,
    pub(crate) local_address: String,
    pub(crate) foreign_address: String,
    pub(crate) state: String,
    pub(crate) pid: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct DisplayRow {
    pub(crate) command: String,
    pub(crate) pid: u32,
    pub(crate) protocol: Protocol,
    pub(crate) local_address: String,
    pub(crate) foreign_address: String,
    pub(crate) state: String,
}
