# lsof

Windows-first `lsof`-style socket, process, and file-in-use inspection.

This project focuses on the Windows workflows that map cleanly from `lsof`:
checking which process owns a port, listing active TCP/UDP sockets, and finding
which process is using a file.

## Scope (vNext)

- `-i` filtering for protocol/host/port (`tcp`, `udp`, `@host`, `:port`)
- `-p` PID filtering
- `-t` terse PID-only output
- accepts `-n` and `-P` for lsof compatibility
- `file <path>` for targeted file-in-use inspection

Current runtime is Windows-first and uses native Windows APIs:

- IP Helper API for TCP/UDP socket ownership
- `QueryFullProcessImageNameW()` for process metadata
- Restart Manager for file-in-use ownership

## Usage

```sh
lsof -i
lsof -i :3000
lsof -i tcp:443
lsof -i udp@127.0.0.1:53
lsof -t -i :8080
lsof -p 1234,5678 -i
lsof file C:\path\to\app.log
```

## Non-goals

- full Unix `lsof` parity
- system-wide open-handle enumeration
- file-descriptor-style output such as `cwd`, `txt`, `mem`, or numeric FD sets
- non-Windows runtime support

## Install

### Windows (Scoop)

```powershell
scoop bucket add rocky https://github.com/i-rocky/scoop-bucket
scoop install lsof
```

### Manual (GitHub Releases)

Download the latest archive from:

`https://github.com/i-rocky/lsof/releases/latest`

Then place `lsof.exe` on your `PATH`.

## Build

```sh
cargo build --release
```

## Test

```sh
cargo test
```

## Release assets

Tagging `v*` publishes:

- `lsof-windows-x86_64-vX.Y.Z.zip`
- `SHA256SUMS.txt`
