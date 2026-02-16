# lsof

`lsof`-style socket and process inspection for Windows.

This tool focuses on the workflow most people use every day on Linux/macOS:
checking which process owns a port and listing active TCP/UDP sockets.

## Scope (v0.1)

- `-i` filtering for protocol/host/port (`tcp`, `udp`, `@host`, `:port`)
- `-p` PID filtering
- `-t` terse PID-only output
- accepts `-n` and `-P` for lsof compatibility

Current runtime is Windows-first and uses:

- `netstat -ano -p tcp/udp`
- `tasklist /FO CSV /NH`

## Usage

```sh
lsof -i
lsof -i :3000
lsof -i tcp:443
lsof -i udp@127.0.0.1:53
lsof -t -i :8080
lsof -p 1234,5678 -i
```

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
- `lsof-linux-x86_64-vX.Y.Z.tar.gz`
- `lsof-linux-aarch64-vX.Y.Z.tar.gz`
- `lsof-darwin-x86_64-vX.Y.Z.tar.gz`
- `lsof-darwin-aarch64-vX.Y.Z.tar.gz`
- `SHA256SUMS.txt`
