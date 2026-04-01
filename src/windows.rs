#[cfg(target_os = "windows")]
mod imp {
    use std::collections::{BTreeSet, HashMap};
    use std::ffi::OsStr;
    use std::mem::size_of;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::slice;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, HANDLE, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::RestartManager::{
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
        RmStartSession,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    use crate::error::Error;
    use crate::model::{FileUseRow, ProcessInfo, Protocol, SocketEntry};

    pub(crate) fn collect_socket_entries() -> Result<Vec<SocketEntry>, Error> {
        let mut entries = Vec::new();
        entries.extend(collect_tcp_v4()?);
        entries.extend(collect_tcp_v6()?);
        entries.extend(collect_udp_v4()?);
        entries.extend(collect_udp_v6()?);
        Ok(entries)
    }

    pub(crate) fn collect_process_map(
        pids: impl IntoIterator<Item = u32>,
    ) -> HashMap<u32, ProcessInfo> {
        let unique: BTreeSet<u32> = pids.into_iter().collect();
        unique
            .into_iter()
            .map(|pid| (pid, query_process_info(pid)))
            .collect()
    }

    pub(crate) fn collect_file_usage(path: &Path) -> Result<Vec<FileUseRow>, Error> {
        let wide_path = encode_wide(path.as_os_str());
        let file_ptrs = [wide_path.as_ptr()];

        let mut session_handle = 0u32;
        let mut session_key = [0u16; (CCH_RM_SESSION_KEY as usize) + 1];
        let start_status =
            unsafe { RmStartSession(&mut session_handle, 0, session_key.as_mut_ptr()) };
        if start_status != NO_ERROR {
            return Err(win32_error("RmStartSession", start_status));
        }

        let _session = RestartManagerSession {
            handle: session_handle,
        };

        let register_status = unsafe {
            RmRegisterResources(
                session_handle,
                file_ptrs.len() as u32,
                file_ptrs.as_ptr(),
                0,
                null(),
                0,
                null(),
            )
        };
        if register_status != NO_ERROR {
            return Err(win32_error("RmRegisterResources", register_status));
        }

        let pids = collect_restart_manager_pids(session_handle)?;
        let rows = pids
            .into_iter()
            .map(|pid| file_use_row_from_pid(pid, query_process_info(pid)))
            .collect();

        Ok(normalize_file_usage_rows(rows))
    }

    fn collect_tcp_v4() -> Result<Vec<SocketEntry>, Error> {
        let buffer = get_ip_table_buffer(
            |ptr, size| unsafe {
                GetExtendedTcpTable(ptr, size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
            },
            "GetExtendedTcpTable(AF_INET)",
        )?;

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let rows =
            unsafe { slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };

        Ok(rows.iter().copied().map(socket_entry_from_tcp_v4).collect())
    }

    fn collect_tcp_v6() -> Result<Vec<SocketEntry>, Error> {
        let buffer = get_ip_table_buffer(
            |ptr, size| unsafe {
                GetExtendedTcpTable(ptr, size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
            },
            "GetExtendedTcpTable(AF_INET6)",
        )?;

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let rows =
            unsafe { slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };

        Ok(rows.iter().copied().map(socket_entry_from_tcp_v6).collect())
    }

    fn collect_udp_v4() -> Result<Vec<SocketEntry>, Error> {
        let buffer = get_ip_table_buffer(
            |ptr, size| unsafe {
                GetExtendedUdpTable(ptr, size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
            },
            "GetExtendedUdpTable(AF_INET)",
        )?;

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let rows =
            unsafe { slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };

        Ok(rows.iter().copied().map(socket_entry_from_udp_v4).collect())
    }

    fn collect_udp_v6() -> Result<Vec<SocketEntry>, Error> {
        let buffer = get_ip_table_buffer(
            |ptr, size| unsafe {
                GetExtendedUdpTable(ptr, size, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
            },
            "GetExtendedUdpTable(AF_INET6)",
        )?;

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let rows =
            unsafe { slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };

        Ok(rows.iter().copied().map(socket_entry_from_udp_v6).collect())
    }

    fn collect_restart_manager_pids(session_handle: u32) -> Result<Vec<u32>, Error> {
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut reboot_reasons = 0u32;
        let first_status = unsafe {
            RmGetList(
                session_handle,
                &mut needed,
                &mut count,
                null_mut(),
                &mut reboot_reasons,
            )
        };

        let proc_count = match first_status {
            NO_ERROR => 0,
            ERROR_MORE_DATA => needed,
            code => return Err(win32_error("RmGetList", code)),
        };

        if proc_count == 0 {
            return Ok(Vec::new());
        }

        let mut processes = vec![RM_PROCESS_INFO::default(); proc_count as usize];
        count = proc_count;
        let second_status = unsafe {
            RmGetList(
                session_handle,
                &mut needed,
                &mut count,
                processes.as_mut_ptr(),
                &mut reboot_reasons,
            )
        };
        if second_status != NO_ERROR {
            return Err(win32_error("RmGetList", second_status));
        }

        Ok(processes
            .into_iter()
            .take(count as usize)
            .map(|process| process.Process.dwProcessId)
            .collect())
    }

    fn socket_entry_from_tcp_v4(row: MIB_TCPROW_OWNER_PID) -> SocketEntry {
        SocketEntry {
            protocol: Protocol::Tcp,
            local_address: format_ipv4_endpoint(row.dwLocalAddr, row.dwLocalPort),
            foreign_address: format_ipv4_endpoint(row.dwRemoteAddr, row.dwRemotePort),
            state: tcp_state_to_string(row.dwState).to_string(),
            pid: row.dwOwningPid,
        }
    }

    fn socket_entry_from_tcp_v6(row: MIB_TCP6ROW_OWNER_PID) -> SocketEntry {
        SocketEntry {
            protocol: Protocol::Tcp,
            local_address: format_ipv6_endpoint(
                row.ucLocalAddr,
                row.dwLocalScopeId,
                row.dwLocalPort,
            ),
            foreign_address: format_ipv6_endpoint(
                row.ucRemoteAddr,
                row.dwRemoteScopeId,
                row.dwRemotePort,
            ),
            state: tcp_state_to_string(row.dwState).to_string(),
            pid: row.dwOwningPid,
        }
    }

    fn socket_entry_from_udp_v4(row: MIB_UDPROW_OWNER_PID) -> SocketEntry {
        SocketEntry {
            protocol: Protocol::Udp,
            local_address: format_ipv4_endpoint(row.dwLocalAddr, row.dwLocalPort),
            foreign_address: udp_foreign_address().to_string(),
            state: String::new(),
            pid: row.dwOwningPid,
        }
    }

    fn socket_entry_from_udp_v6(row: MIB_UDP6ROW_OWNER_PID) -> SocketEntry {
        SocketEntry {
            protocol: Protocol::Udp,
            local_address: format_ipv6_endpoint(
                row.ucLocalAddr,
                row.dwLocalScopeId,
                row.dwLocalPort,
            ),
            foreign_address: udp_foreign_address().to_string(),
            state: String::new(),
            pid: row.dwOwningPid,
        }
    }

    fn query_process_info(pid: u32) -> ProcessInfo {
        if pid == 0 {
            return unknown_process();
        }

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return unknown_process();
        }
        let handle = OwnedHandle(handle);

        process_info_from_path(query_process_path(handle.0))
    }

    fn process_info_from_path(process_path: Option<String>) -> ProcessInfo {
        let Some(process_path) = process_path else {
            return unknown_process();
        };

        let command = command_from_process_path(&process_path)
            .unwrap_or("<unknown>")
            .to_string();

        ProcessInfo {
            command,
            process_path,
        }
    }

    fn file_use_row_from_pid(pid: u32, info: ProcessInfo) -> FileUseRow {
        FileUseRow {
            command: info.command,
            pid,
            process_path: info.process_path,
        }
    }

    fn normalize_file_usage_rows(mut rows: Vec<FileUseRow>) -> Vec<FileUseRow> {
        rows.sort_by(|a, b| {
            a.pid
                .cmp(&b.pid)
                .then(a.command.cmp(&b.command))
                .then(a.process_path.cmp(&b.process_path))
        });
        rows.dedup_by(|a, b| a.pid == b.pid && a.process_path == b.process_path);
        rows
    }

    fn query_process_path(handle: HANDLE) -> Option<String> {
        let mut capacity = 260usize;

        while capacity <= 32_768 {
            let mut buffer = vec![0u16; capacity];
            let mut size = capacity as u32;
            let ok = unsafe {
                QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    buffer.as_mut_ptr(),
                    &mut size,
                )
            };
            if ok != 0 {
                buffer.truncate(size as usize);
                return Some(String::from_utf16_lossy(&buffer));
            }

            capacity *= 2;
        }

        None
    }

    fn command_from_process_path(process_path: &str) -> Option<&str> {
        Path::new(process_path)
            .file_name()
            .and_then(|value| value.to_str())
    }

    fn format_ipv4_endpoint(address: u32, port: u32) -> String {
        let ip = Ipv4Addr::from(u32::from_be(address));
        let port = decode_port(port);
        format!("{ip}:{port}")
    }

    fn format_ipv6_endpoint(address: [u8; 16], scope_id: u32, port: u32) -> String {
        let ip = Ipv6Addr::from(address);
        let port = decode_port(port);
        if scope_id == 0 {
            format!("[{ip}]:{port}")
        } else {
            format!("[{ip}%{scope_id}]:{port}")
        }
    }

    fn udp_foreign_address() -> &'static str {
        "*:*"
    }

    fn decode_port(raw: u32) -> u16 {
        u16::from_be((raw & 0xffff) as u16)
    }

    fn tcp_state_to_string(state: u32) -> &'static str {
        match state {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "",
        }
    }

    fn get_ip_table_buffer(
        mut loader: impl FnMut(*mut core::ffi::c_void, *mut u32) -> u32,
        context: &str,
    ) -> Result<Vec<u8>, Error> {
        let mut size = 0u32;
        let first = loader(null_mut(), &mut size);
        if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
            return Err(win32_error(context, first));
        }

        let mut buffer = vec![0u8; size.max(size_of::<u32>() as u32) as usize];
        let second = loader(buffer.as_mut_ptr().cast(), &mut size);
        if second != NO_ERROR {
            return Err(win32_error(context, second));
        }

        Ok(buffer)
    }

    fn encode_wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn unknown_process() -> ProcessInfo {
        ProcessInfo {
            command: "<unknown>".to_string(),
            process_path: "<unknown>".to_string(),
        }
    }

    fn win32_error(context: &str, code: u32) -> Error {
        Error::Runtime(format!("{context} failed with Win32 error {code}"))
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct RestartManagerSession {
        handle: u32,
    }

    impl Drop for RestartManagerSession {
        fn drop(&mut self) {
            unsafe {
                RmEndSession(self.handle);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn raw_port(port: u16) -> u32 {
            u32::from(port.to_be())
        }

        #[test]
        fn format_ipv4_endpoint_formats_local_and_remote() {
            assert_eq!(
                format_ipv4_endpoint(0x0100007f, raw_port(8080)),
                "127.0.0.1:8080"
            );
            assert_eq!(format_ipv4_endpoint(0, 0), "0.0.0.0:0");
        }

        #[test]
        fn format_ipv6_endpoint_brackets_address() {
            assert_eq!(
                format_ipv6_endpoint(Ipv6Addr::LOCALHOST.octets(), 0, raw_port(8080)),
                "[::1]:8080"
            );
        }

        #[test]
        fn format_ipv6_endpoint_includes_scope_id() {
            assert_eq!(
                format_ipv6_endpoint(
                    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets(),
                    4,
                    raw_port(5353),
                ),
                "[fe80::1%4]:5353"
            );
        }

        #[test]
        fn udp_foreign_address_is_stable() {
            assert_eq!(udp_foreign_address(), "*:*");
        }

        #[test]
        fn decode_port_handles_byte_order() {
            assert_eq!(decode_port(raw_port(8080)), 8080);
            assert_eq!(decode_port(raw_port(53)), 53);
        }

        #[test]
        fn tcp_state_to_string_maps_all_known_states() {
            let states = [
                (1, "CLOSED"),
                (2, "LISTEN"),
                (3, "SYN_SENT"),
                (4, "SYN_RCVD"),
                (5, "ESTABLISHED"),
                (6, "FIN_WAIT1"),
                (7, "FIN_WAIT2"),
                (8, "CLOSE_WAIT"),
                (9, "CLOSING"),
                (10, "LAST_ACK"),
                (11, "TIME_WAIT"),
                (12, "DELETE_TCB"),
                (999, ""),
            ];

            for (state, expected) in states {
                assert_eq!(tcp_state_to_string(state), expected);
            }
        }

        #[test]
        fn socket_entry_from_tcp_v4_maps_row() {
            let row = MIB_TCPROW_OWNER_PID {
                dwState: 5,
                dwLocalAddr: 0x0100007f,
                dwLocalPort: raw_port(8080),
                dwRemoteAddr: 0,
                dwRemotePort: 0,
                dwOwningPid: 42,
            };

            let entry = socket_entry_from_tcp_v4(row);
            assert_eq!(entry.protocol, Protocol::Tcp);
            assert_eq!(entry.local_address, "127.0.0.1:8080");
            assert_eq!(entry.foreign_address, "0.0.0.0:0");
            assert_eq!(entry.state, "ESTABLISHED");
            assert_eq!(entry.pid, 42);
        }

        #[test]
        fn socket_entry_from_tcp_v6_maps_row() {
            let row = MIB_TCP6ROW_OWNER_PID {
                ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
                dwLocalScopeId: 0,
                dwLocalPort: raw_port(443),
                ucRemoteAddr: Ipv6Addr::UNSPECIFIED.octets(),
                dwRemoteScopeId: 0,
                dwRemotePort: 0,
                dwState: 2,
                dwOwningPid: 99,
            };

            let entry = socket_entry_from_tcp_v6(row);
            assert_eq!(entry.protocol, Protocol::Tcp);
            assert_eq!(entry.local_address, "[::1]:443");
            assert_eq!(entry.foreign_address, "[::]:0");
            assert_eq!(entry.state, "LISTEN");
            assert_eq!(entry.pid, 99);
        }

        #[test]
        fn socket_entry_from_udp_v4_maps_row() {
            let row = MIB_UDPROW_OWNER_PID {
                dwLocalAddr: 0x0100007f,
                dwLocalPort: raw_port(5353),
                dwOwningPid: 11,
            };

            let entry = socket_entry_from_udp_v4(row);
            assert_eq!(entry.protocol, Protocol::Udp);
            assert_eq!(entry.local_address, "127.0.0.1:5353");
            assert_eq!(entry.foreign_address, "*:*");
            assert_eq!(entry.state, "");
            assert_eq!(entry.pid, 11);
        }

        #[test]
        fn socket_entry_from_udp_v6_maps_row() {
            let row = MIB_UDP6ROW_OWNER_PID {
                ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
                dwLocalScopeId: 0,
                dwLocalPort: raw_port(5353),
                dwOwningPid: 12,
            };

            let entry = socket_entry_from_udp_v6(row);
            assert_eq!(entry.protocol, Protocol::Udp);
            assert_eq!(entry.local_address, "[::1]:5353");
            assert_eq!(entry.foreign_address, "*:*");
            assert_eq!(entry.state, "");
            assert_eq!(entry.pid, 12);
        }

        #[test]
        fn process_info_from_path_uses_basename() {
            let info = process_info_from_path(Some("C:\\Program Files\\App\\app.exe".to_string()));
            assert_eq!(info.command, "app.exe");
            assert_eq!(info.process_path, "C:\\Program Files\\App\\app.exe");
        }

        #[test]
        fn process_info_from_path_handles_unicode_path() {
            let info = process_info_from_path(Some("C:\\工具\\应用.exe".to_string()));
            assert_eq!(info.command, "应用.exe");
        }

        #[test]
        fn process_info_from_path_falls_back_to_unknown_for_missing_path() {
            let info = process_info_from_path(None);
            assert_eq!(info, unknown_process());
        }

        #[test]
        fn query_process_info_pid_zero_returns_unknown() {
            let info = query_process_info(0);
            assert_eq!(info, unknown_process());
        }

        #[test]
        fn normalize_file_usage_rows_sorts_and_deduplicates() {
            let rows = vec![
                FileUseRow {
                    command: "b.exe".to_string(),
                    pid: 20,
                    process_path: "C:\\b.exe".to_string(),
                },
                FileUseRow {
                    command: "a.exe".to_string(),
                    pid: 10,
                    process_path: "C:\\a.exe".to_string(),
                },
                FileUseRow {
                    command: "b.exe".to_string(),
                    pid: 20,
                    process_path: "C:\\b.exe".to_string(),
                },
            ];

            let normalized = normalize_file_usage_rows(rows);
            assert_eq!(normalized.len(), 2);
            assert_eq!(normalized[0].pid, 10);
            assert_eq!(normalized[1].pid, 20);
        }

        #[test]
        fn normalize_file_usage_rows_handles_empty_input() {
            assert!(normalize_file_usage_rows(Vec::new()).is_empty());
        }

        #[test]
        fn file_use_row_from_pid_preserves_resolved_process_info() {
            let row = file_use_row_from_pid(
                77,
                ProcessInfo {
                    command: "tool.exe".to_string(),
                    process_path: "C:\\tool.exe".to_string(),
                },
            );

            assert_eq!(row.command, "tool.exe");
            assert_eq!(row.pid, 77);
            assert_eq!(row.process_path, "C:\\tool.exe");
        }

        #[test]
        fn win32_error_formats_consistently() {
            assert_eq!(
                win32_error("RmGetList", 5).to_string(),
                "RmGetList failed with Win32 error 5"
            );
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) use imp::{collect_file_usage, collect_process_map, collect_socket_entries};

#[cfg(not(target_os = "windows"))]
pub(crate) fn collect_socket_entries() -> Result<Vec<crate::model::SocketEntry>, crate::error::Error>
{
    Err(crate::error::Error::Runtime(
        "this implementation currently supports Windows runtime only".to_string(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn collect_process_map(
    _pids: impl IntoIterator<Item = u32>,
) -> std::collections::HashMap<u32, crate::model::ProcessInfo> {
    std::collections::HashMap::new()
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn collect_file_usage(
    _path: &std::path::Path,
) -> Result<Vec<crate::model::FileUseRow>, crate::error::Error> {
    Err(crate::error::Error::Runtime(
        "this implementation currently supports Windows runtime only".to_string(),
    ))
}
