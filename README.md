# EventBox

**One-click desktop app for running the EventBox LAN server at dance competitions.**

No terminal. No dependencies. Just download, install, and go.

---

## Download & Install

| Platform | Download | How to Install |
|----------|----------|----------------|
| **Windows** | [EventBox-Windows.msi](https://github.com/W-A-I-T/EventBox/releases/latest/download/EventBox-Windows.msi) | Double-click the `.msi` file |
| **macOS** | [EventBox-Mac.dmg](https://github.com/W-A-I-T/EventBox/releases/latest/download/EventBox-Mac.dmg) | Open the `.dmg`, drag EventBox to Applications |
| **Linux (AppImage)** ⭐ | [EventBox-Linux.AppImage](https://github.com/W-A-I-T/EventBox/releases/latest/download/EventBox-Linux.AppImage) | Right-click → Properties → Permissions → Allow executing, then double-click |
| **Linux (.deb)** | [EventBox-Linux.deb](https://github.com/W-A-I-T/EventBox/releases/latest/download/EventBox-Linux.deb) | `sudo dpkg -i EventBox-Linux.deb` or double-click |

> **Everything is bundled.** No Deno, no Rust, no Node.js needed on the user's machine.

> **Linux users:** The **AppImage** is the recommended format. It works on all distributions and supports auto-updates. The `.deb` package requires `libwebkit2gtk-4.0` which is only available on Ubuntu 22.04 and earlier. **Ubuntu 24.04+ users must use the AppImage** (the `.deb` will fail to install due to the missing `libwebkit2gtk-4.0-37` package).

---

## How to Use

1. **Open EventBox** from your Applications menu or desktop
2. **Paste your Event ID** and click **Start**
3. The server starts in the background with a **system tray icon**
4. A **room code** and **QR code** appear on the dashboard
5. Staff connect their devices by scanning the QR code or entering the room code
6. **Close the window** — the server keeps running in the tray
7. Click the **tray icon** to open the dashboard again, or **Quit** to stop everything

### Command-Line Options (optional)

```bash
# Pre-configure event ID
./EventBox --event-id "your-event-uuid"

# Custom port (default: 8787)
./EventBox --event-id "your-event-uuid" --port 9090

# Or use environment variables
EVENTBOX_EVENT_ID="your-event-uuid" EVENTBOX_PORT=9090 ./EventBox
```

---

## For Developers

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| **Rust** | 1.70+ | [rustup.rs](https://rustup.rs) |
| **Deno** | 2.x | [deno.land](https://deno.land/#installation) |
| **Tauri CLI** | 2.x | `cargo install tauri-cli --version "^2"` |

**Linux only:**
```bash
sudo apt install libwebkit2gtk-4.1-dev build-essential libssl-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
```

**macOS only:**
```bash
xcode-select --install
```

**Windows only:**
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with "C++ build tools"
- [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) (pre-installed on Windows 11)

### Development

```bash
npm run tauri:dev
```

This compiles the server into a standalone binary, then launches the app with hot-reload.

### Production Build

```bash
npm run tauri:build
```

This:
1. Compiles `server.ts` into a standalone `eventbox-server` binary (via `deno compile`)
2. Builds the Tauri app with the server bundled inside
3. Produces platform-specific installers in `src-tauri/target/release/bundle/`

### Cross-Platform Server Compilation

```bash
# Current platform (auto-detect)
npm run compile-server

# Specific targets
npm run compile-server:windows   # x86_64-pc-windows-msvc
npm run compile-server:mac-arm   # aarch64-apple-darwin
npm run compile-server:mac-intel # x86_64-apple-darwin
npm run compile-server:linux     # x86_64-unknown-linux-gnu
```

---

## CI/CD

A GitHub Actions workflow (`.github/workflows/build.yml`) is included that:

1. Builds for **Windows**, **macOS**, and **Linux** in parallel
2. Compiles the server binary for each target platform
3. Produces `.msi`, `.dmg`, `.deb`, and `.AppImage` installers
4. On tagged releases (`v*`), automatically creates a GitHub Release with all installers attached

### Triggering a Release

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow runs automatically and publishes the installers to the Releases page.

---

## Architecture

```
EventBox/
├── .github/workflows/
│   └── build.yml               # CI: multi-platform build & release
├── src-tauri/
│   ├── Cargo.toml              # Rust dependencies (Tauri, serde, local-ip-address)
│   ├── Cargo.lock              # Locked dependency versions
│   ├── tauri.conf.json         # Window config, bundling, system tray
│   ├── build.rs                # Tauri build script
│   ├── icons/                  # App icons (PNG, ICO, ICNS)
│   ├── src/
│   │   └── main.rs             # Rust: spawn server, system tray, IPC
│   └── resources/
│       ├── server.ts           # EventBox LAN server source
│       └── eventbox-server*    # Compiled server binary (built during build)
├── src/
│   └── index.html               # Dashboard UI (room code, QR, IPs, controls)
├── package.json                # Build scripts
├── .gitignore
├── LICENSE                     # GPL-3.0
└── README.md
```

### How It Works

- **Tauri** (Rust) creates a native desktop window with a webview
- On start, the Rust backend spawns the **compiled EventBox server** as a subprocess
- The server generates a **room code** and prints it to stdout
- Rust captures the room code and sends it to the **dashboard UI** via Tauri events
- The **system tray** lets users Start/Stop the server and Quit the app
- Closing the window **hides** it to the tray — the server keeps running

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "WebView2 not found" (Windows) | Install from [Microsoft](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) |
| Build fails on Linux | Install webkit2gtk dev packages (see Prerequisites) |
| Server won't start | Check that port 8787 isn't already in use |
| App won't open on macOS | Right-click > Open (first time only, to bypass Gatekeeper) |
| `.deb` install fails with `libwebkit2gtk-4.0-37` error | You are on Ubuntu 24.04+. Use the **AppImage** instead |
| No update notification | Auto-update only works with AppImage on Linux. `.deb` users will see an in-app banner when a new version is available |

---

## License

[GPL-3.0](LICENSE)
