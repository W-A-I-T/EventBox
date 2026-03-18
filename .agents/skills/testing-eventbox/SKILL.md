# Testing EventBox Desktop App

## Prerequisites

### Linux (Ubuntu 22.04)
```bash
# Install Deno
curl -fsSL https://deno.land/install.sh | sh
export PATH="$HOME/.deno/bin:$PATH"

# Install Rust (stable toolchain — Tauri v2 no longer needs 1.85 pin)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Install Tauri CLI v2
cargo install tauri-cli --version "^2"

# Install Linux dependencies (note: 4.1, not 4.0)
sudo apt-get update && sudo apt-get install -y \
  libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
  librsvg2-dev patchelf libfuse2 libssl-dev
```

## Building

### Compile the server binary (required before building the app)
```bash
# From repo root
deno compile --allow-net --allow-read --allow-write --allow-env --allow-ffi --unstable-ffi \
  --output src-tauri/resources/eventbox-server src-tauri/resources/server.ts
```

### Build the Tauri app
```bash
cargo tauri build
# Outputs: src-tauri/target/release/bundle/deb/*.deb, *.rpm, *.AppImage
```

### Dev mode
```bash
cargo tauri dev
```

## Testing the App

### Important: WebKitGTK limitation on headless Linux
Tauri apps use WebKitGTK which does NOT accept synthetic mouse/keyboard events from xdotool.
You CANNOT click buttons or type in the Tauri webview via xdotool automation.

### Workarounds for automated testing:
1. **Use `--event-id` CLI flag** to auto-start the server (bypasses UI button click):
   ```bash
   event-box --event-id <uuid>
   ```
2. **Test JavaScript separately** by opening `src/index.html` in Chrome browser
3. **Verify via terminal output** - the app prints `[EventBox] Room code: XXXXXX` to stdout
4. **Check process listing** - `ps aux | grep eventbox-server` to confirm bundled binary is used

### Test Case: Verify bundled binary is used (not Deno)
```bash
# Install the .deb
sudo dpkg -i src-tauri/target/release/bundle/deb/event-box_*.deb

# Run with event ID (auto-starts server)
DISPLAY=:0 event-box --event-id <event-uuid> 2>&1 &
sleep 5

# Verify bundled binary is running
ps aux | grep eventbox-server  # Should show /usr/lib/event-box/resources/eventbox-server
ps aux | grep -v grep | grep deno  # Should show nothing (no deno process)
curl -s http://localhost:8787/  # Should return HTML
```

### Test Case: Error when binary is missing
```bash
sudo mv /usr/lib/event-box/resources/eventbox-server /usr/lib/event-box/resources/eventbox-server.bak
PATH=/usr/bin:/bin DISPLAY=:0 event-box --event-id test-id 2>&1
# Should print: "Failed to start server: No such file or directory"
sudo mv /usr/lib/event-box/resources/eventbox-server.bak /usr/lib/event-box/resources/eventbox-server
```

### Test Case: JavaScript error UX
Open `src/index.html` in Chrome and use the console:
```javascript
// Test persistent error with Dismiss button
showError('Test error message', true);
// Wait 10+ seconds - error should NOT auto-hide
// Click Dismiss - error should hide

// Test race condition fix
showError('temp', false);
setTimeout(() => showError('persistent', true), 500);
// After 10s the persistent error should still be visible
```

## Key Architecture Notes
- `src-tauri/src/lib.rs`: Rust backend — server lifecycle, CLI arg parsing, resource resolution
  (NOTE: Tauri v2 uses lib.rs as the main entry point, not main.rs. main.rs is a thin wrapper.)
- `src/index.html`: Frontend UI - single HTML file with inline JS/CSS
- `src-tauri/resources/server.ts`: Deno server source (compiled to `eventbox-server` binary)
- `src-tauri/tauri.conf.json`: Tauri config - resources glob, bundle settings, dependencies
- Server binary preference order: compiled `eventbox-server` > `deno run server.ts` > error
- `--event-id` CLI flag triggers auto-start in the `setup` hook (main.rs)
- The `setup` hook fires before the webview loads JS, so `server-status` events from auto-start may be missed by the frontend
