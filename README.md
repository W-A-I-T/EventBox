# EventBox Desktop App

A native desktop application that bundles the EventBox LAN server. One-click start — no terminal needed.

## What It Does

1. **Launches the Deno server** as a background process
2. **Shows a dashboard** with room code, QR code, and local IP addresses
3. **System tray icon** — server keeps running when you close the window
4. **Auto-starts** when an event ID is configured

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| **Rust** | 1.70+ | [rustup.rs](https://rustup.rs) |
| **Deno** | 1.40+ | [deno.land](https://deno.land/#installation) |
| **Tauri CLI** | 1.x | `cargo install tauri-cli` |

### Platform-Specific

**Windows:**
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with "C++ build tools" workload
- [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) (pre-installed on Windows 11)

**macOS:**
- Xcode Command Line Tools: `xcode-select --install`

**Linux:**
```bash
# Debian/Ubuntu
sudo apt install libwebkit2gtk-4.0-dev build-essential curl wget file \
  libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev

# Fedora
sudo dnf install webkit2gtk4.0-devel openssl-devel gtk3-devel \
  libappindicator-gtk3-devel librsvg2-devel
```

## Build Instructions

### 1. Copy the server file

```bash
npm run copy-server
```

This copies the latest server.ts into `src-tauri/resources/`. (In the standalone repo, the server is already bundled.)

### 2. Development mode

```bash
npm run tauri:dev
```

Or directly:
```bash
cd src-tauri && cargo tauri dev
```

This opens the app with hot-reload and Rust debugging.

### 3. Production build

```bash
npm run tauri:build
```

Or directly:
```bash
cd src-tauri && cargo tauri build
```

Output locations:
- **Windows:** `src-tauri/target/release/bundle/msi/EventBox_0.1.0_x64_en-US.msi`
- **macOS:** `src-tauri/target/release/bundle/dmg/EventBox_0.1.0_aarch64.dmg`
- **Linux:** `src-tauri/target/release/bundle/deb/eventbox_0.1.0_amd64.deb` and `.AppImage`

### 4. Run with event ID

```bash
# Via environment variable
EVENTBOX_EVENT_ID="your-event-uuid" ./EventBox

# Via CLI argument
./EventBox --event-id "your-event-uuid"

# With custom port
./EventBox --event-id "your-event-uuid" --port 9090
```

## CI Build (GitHub Actions)

Create `.github/workflows/build.yml`:

```yaml
name: Build EventBox
on:
  push:
    tags: ['v*']

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
          - os: macos-latest
            target: aarch64-apple-darwin
          - os: windows-latest
            target: x86_64-pc-windows-msvc
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: denoland/setup-deno@v1
      - uses: dtolnay/rust-toolchain@stable
      - name: Install Linux deps
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y libwebkit2gtk-4.0-dev libgtk-3-dev \
            libayatana-appindicator3-dev librsvg2-dev
      - name: Build
        run: npm run tauri:build
      - uses: actions/upload-artifact@v4
        with:
          name: eventbox-${{ matrix.target }}
          path: src-tauri/target/release/bundle/**
```

## Architecture

```
EventBox/
├── src-tauri/
│   ├── Cargo.toml          # Rust dependencies
│   ├── tauri.conf.json      # Window config, bundling
│   ├── build.rs             # Tauri build script
│   ├── src/
│   │   └── main.rs          # Spawn Deno, system tray, IPC
│   └── resources/
│       └── server.ts        # Bundled EventBox server
├── src/
│   └── dashboard.html       # Dashboard UI (Tauri webview)
├── package.json             # Build scripts
├── LICENSE                  # GPL-3.0
└── README.md                # This file
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Deno not found" | Install Deno and ensure it's in your PATH |
| "WebView2 not found" (Windows) | Install from [Microsoft](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) |
| Build fails on Linux | Install the webkit2gtk dev packages (see Prerequisites) |
| Server won't start | Check that port 8787 isn't already in use |
| No QR code shown | QR generation requires a JS library — see dashboard.html comments |
