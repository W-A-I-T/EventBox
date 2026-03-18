#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    Emitter, Manager,
};

#[cfg(unix)]
extern crate libc;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct ServerState {
    child: Option<Child>,
    room_code: Option<String>,
    port: u16,
    event_id: String,
    /// Monotonically increasing counter bumped each time a new server
    /// process is spawned.  The stderr reader thread captures the
    /// generation at spawn time and compares it later to detect whether
    /// the process it was monitoring is still the "current" one.
    generation: u64,
}

// ---------------------------------------------------------------------------
// PID file management (Fix #7: orphan cleanup)
// ---------------------------------------------------------------------------

/// PID file path for detecting orphaned server processes from previous crashes.
fn pidfile_path() -> PathBuf {
    std::env::temp_dir().join("eventbox-server.pid")
}

fn write_pidfile(pid: u32) {
    if let Err(e) = std::fs::write(pidfile_path(), pid.to_string()) {
        eprintln!("[EventBox] Failed to write PID file: {}", e);
    }
}

/// Check whether a given PID belongs to an eventbox-server process.
/// Returns false if the process doesn't exist or isn't ours.
fn is_eventbox_process(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        // Read /proc/<pid>/cmdline — fields are NUL-separated
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
            return cmdline.contains("eventbox-server") || cmdline.contains("server.ts");
        }
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "args="])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            let args = String::from_utf8_lossy(&output.stdout);
            return args.contains("eventbox-server") || args.contains("server.ts");
        }
        return false;
    }
    #[cfg(windows)]
    {
        if let Ok(output) = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            return text.contains("eventbox-server") || text.contains("deno");
        }
        return false;
    }
}

/// Attempt to clean up a leftover server process from a previous crash.
/// Verifies the PID still belongs to an eventbox-server before killing to
/// avoid terminating an unrelated process that reused the PID.
fn cleanup_orphan() {
    let path = pidfile_path();
    if let Ok(contents) = std::fs::read_to_string(&path) {
        if let Ok(pid) = contents.trim().parse::<u32>() {
            eprintln!(
                "[EventBox] Found leftover PID file (pid={}), checking process",
                pid
            );
            if !is_eventbox_process(pid) {
                eprintln!(
                    "[EventBox] PID {} is not an eventbox-server process (or already exited), removing stale PID file",
                    pid
                );
                let _ = std::fs::remove_file(&path);
                return;
            }
            eprintln!("[EventBox] PID {} confirmed as eventbox-server, sending kill signal", pid);
            #[cfg(unix)]
            {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            #[cfg(windows)]
            {
                let _ = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        let _ = std::fs::remove_file(&path);
    }
}

fn remove_pidfile() {
    let _ = std::fs::remove_file(pidfile_path());
}

// ---------------------------------------------------------------------------
// Server binary resolution
// ---------------------------------------------------------------------------

/// Check whether a file looks like a valid Deno standalone binary by
/// verifying the trailing magic bytes.  Deno standalone binaries end with
/// the 8-byte trailer "d3n0l4nd".  Returns `true` when the trailer is
/// present, `false` when it is definitively missing, and `true`
/// (optimistic) on any I/O error so we never block a binary that might
/// actually work.
///
/// The "d3n0l4nd" trailer has been stable across Deno 1.x and 2.x.
/// If a future Deno version changes this magic, the check will return
/// `false` for valid binaries — but the fallback loop in `start_server`
/// will still try them via `try_wait()` crash detection, and ultimately
/// fall through to system Deno + server.ts which always works.
fn has_deno_standalone_trailer(path: &std::path::Path) -> bool {
    use std::io::{Seek, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return true, // can't open → let caller handle existence
    };
    if file.seek(SeekFrom::End(-8)).is_err() {
        return true; // file too small → let caller try it
    }
    let mut magic = [0u8; 8];
    if file.read_exact(&mut magic).is_err() {
        return true;
    }
    &magic == b"d3n0l4nd"
}

enum ServerBinary {
    /// A compiled native eventbox-server binary
    Native(PathBuf),
    /// Bundled sidecar Deno binary (ships with the app)
    SidecarDeno(PathBuf, PathBuf), // (deno_path, server_ts_path)
    /// System-installed Deno
    SystemDeno(PathBuf), // server_ts_path
}

/// Collects candidate resource directories in priority order.
///
/// On Linux .deb installs the bundler places resources under
/// `/usr/lib/<productName>/` but Tauri's `resource_dir()` resolves using
/// `package_info.name` which *should* match the productName.  In practice
/// the canonicalize() call inside Tauri can fail if the directory hasn't
/// been created yet or if there's a name mismatch.  This helper returns
/// all plausible directories so callers can search each one.
fn resource_dir_candidates(app: &tauri::AppHandle) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();

    // 1. Tauri's built-in resource_dir (the "official" path)
    match app.path().resource_dir() {
        Ok(rd) => {
            eprintln!("[EventBox] resource_dir() = {}", rd.display());
            if !dirs.contains(&rd) {
                dirs.push(rd);
            }
        }
        Err(e) => {
            eprintln!("[EventBox] resource_dir() error: {e}");
        }
    }

    // 2. Linux-specific .deb / AppImage fallback paths
    //    The .deb bundler uses productName from tauri.conf.json for the
    //    lib directory (e.g. /usr/lib/EventBox/) while resource_dir() may
    //    resolve to a different name.  Try the well-known layout.
    #[cfg(target_os = "linux")]
    {
        if let Ok(exe) = std::env::current_exe() {
            // prefix = /usr  when exe = /usr/bin/eventbox-desktop
            if let Some(prefix) = exe.parent().and_then(|d| d.parent()) {
                let product = app
                    .config()
                    .product_name
                    .as_deref()
                    .unwrap_or("EventBox");
                let exe_stem = exe
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("eventbox-desktop");

                // Collect unique directory names to try
                let mut names: Vec<&str> = Vec::new();
                for n in [product, exe_stem, "EventBox", "eventbox-desktop"] {
                    if !names.contains(&n) {
                        names.push(n);
                    }
                }

                for name in &names {
                    let candidate = prefix.join("lib").join(name);
                    if !dirs.contains(&candidate) {
                        dirs.push(candidate);
                    }
                }
            }
        }
    }

    dirs
}

/// Resolves all available server binary candidates in priority order:
///
/// 1. Compiled eventbox-server binary next to app executable (validated)
/// 2. Compiled eventbox-server binary in Tauri resource directories (validated)
/// 3. Bundled sidecar Deno + resources/server.ts
/// 4. System Deno (`deno` on PATH) + resources/server.ts
///
/// Native binaries are validated for the Deno standalone trailer to skip
/// corrupt or incompatible builds, allowing automatic fallback to Deno.
fn resolve_server_binaries(app: &tauri::AppHandle) -> Vec<(ServerBinary, &'static str)> {
    let bin_name = if cfg!(target_os = "windows") {
        "eventbox-server.exe"
    } else {
        "eventbox-server"
    };

    // Compute resource directory candidates once to avoid duplicate logging.
    let resource_dirs = resource_dir_candidates(app);

    let mut candidates: Vec<(ServerBinary, &'static str)> = Vec::new();
    let mut tried: Vec<String> = Vec::new();

    // 1. Compiled binary next to app executable
    if let Ok(exe_dir) = std::env::current_exe().map(|p| p.parent().unwrap_or(&p).to_path_buf()) {
        let candidate = exe_dir.join(bin_name);
        eprintln!("[EventBox] try exe-dir: {}", candidate.display());
        tried.push(candidate.display().to_string());
        if candidate.exists() {
            if has_deno_standalone_trailer(&candidate) {
                eprintln!("[EventBox] found server binary (exe-dir)");
                candidates.push((ServerBinary::Native(candidate), "bundled server"));
            } else {
                eprintln!(
                    "[EventBox] binary at {} exists but is not a valid Deno standalone (missing trailer) \u{2014} skipping",
                    candidate.display()
                );
            }
        }
    }

    // 2. Compiled binary in resource directories
    //    bundle.resources preserves relative paths, so "resources/eventbox-server*"
    //    ends up at <resource_dir>/resources/eventbox-server.
    for rd in &resource_dirs {
        for sub in ["resources", ""] {
            let candidate = if sub.is_empty() {
                rd.join(bin_name)
            } else {
                rd.join(sub).join(bin_name)
            };

            let display = candidate.display().to_string();
            if tried.contains(&display) {
                continue;
            }

            eprintln!("[EventBox] try resource: {}", display);
            tried.push(display);
            if candidate.exists() {
                if has_deno_standalone_trailer(&candidate) {
                    eprintln!("[EventBox] found server binary (resource)");
                    candidates.push((ServerBinary::Native(candidate), "bundled server"));
                } else {
                    eprintln!(
                        "[EventBox] binary at {} exists but is not a valid Deno standalone (missing trailer) \u{2014} skipping",
                        candidate.display()
                    );
                }
            }
        }
    }

    // Resolve server.ts for Deno-based fallbacks (reuse cached candidate dirs)
    let server_ts = resource_dirs
        .iter()
        .flat_map(|rd| [rd.join("resources/server.ts"), rd.join("server.ts")])
        .find(|p| p.exists());

    // 3. Bundled sidecar Deno
    let sidecar_deno = resolve_sidecar_deno_path();
    if let (Some(deno_path), Some(ts_path)) = (&sidecar_deno, &server_ts) {
        candidates.push((
            ServerBinary::SidecarDeno(deno_path.clone(), ts_path.clone()),
            "bundled Deno",
        ));
    }

    // 4. System Deno on PATH
    if let Some(ts_path) = &server_ts {
        if which_deno().is_some() {
            candidates.push((ServerBinary::SystemDeno(ts_path.clone()), "system Deno"));
        }
    }

    if candidates.is_empty() {
        eprintln!(
            "[EventBox] No server binary or Deno runtime found.\n\
             Paths tried:\n  {}",
            tried.join("\n  ")
        );
    }

    candidates
}

/// Find the sidecar Deno binary that Tauri bundles via `externalBin`.
/// Tauri renames sidecars to `{name}-{target_triple}[.exe]` at build time.
fn resolve_sidecar_deno_path() -> Option<PathBuf> {
    // The sidecar lives next to the app executable after bundling
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))?;

    let target_triple = tauri_target_triple();

    let candidates = if cfg!(target_os = "windows") {
        vec![
            exe_dir.join(format!("deno-{}.exe", target_triple)),
            exe_dir.join("deno.exe"),
        ]
    } else {
        vec![
            exe_dir.join(format!("deno-{}", target_triple)),
            exe_dir.join("deno"),
        ]
    };

    candidates.into_iter().find(|p| p.exists())
}

/// Check if `deno` is available on the system PATH.
fn which_deno() -> Option<PathBuf> {
    let name = if cfg!(target_os = "windows") {
        "deno.exe"
    } else {
        "deno"
    };
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.exists())
    })
}

/// Return the Rust target triple at compile time for sidecar name matching.
fn tauri_target_triple() -> &'static str {
    option_env!("TAURI_ENV_TARGET_TRIPLE").unwrap_or("unknown-unknown-unknown")
}

// ---------------------------------------------------------------------------
// Deno check (IPC command)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct DenoStatus {
    available: bool,
    source: String,  // "sidecar", "system", "none"
    version: String, // e.g. "deno 1.42.0" or ""
    install_url: String,
}

fn get_deno_version(deno_path: &std::path::Path) -> String {
    Command::new(deno_path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8(o.stdout)
                .ok()
                .map(|s| s.lines().next().unwrap_or("").trim().to_string())
        })
        .unwrap_or_default()
}

#[tauri::command]
fn check_deno(app_handle: tauri::AppHandle) -> DenoStatus {
    let install_url = "https://deno.land/#installation".to_string();

    // Check sidecar first
    if let Some(sidecar) = resolve_sidecar_deno_path() {
        let version = get_deno_version(&sidecar);
        if !version.is_empty() {
            return DenoStatus {
                available: true,
                source: "sidecar".into(),
                version,
                install_url,
            };
        }
    }

    // Check system Deno
    if let Some(system_deno) = which_deno() {
        let version = get_deno_version(&system_deno);
        if !version.is_empty() {
            return DenoStatus {
                available: true,
                source: "system".into(),
                version,
                install_url,
            };
        }
    }

    // Suppress unused variable warning -- app_handle is required by the
    // #[tauri::command] signature but only used indirectly via the global
    // sidecar/system checks above.
    let _ = &app_handle;

    DenoStatus {
        available: false,
        source: "none".into(),
        version: String::new(),
        install_url,
    }
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

fn start_server(state: &Mutex<ServerState>, app: &tauri::AppHandle) -> Result<(), String> {
    // Acquire the lock briefly to check state and read config, then drop it
    // so the fallback loop (which may sleep) does not hold the mutex.
    let (port, event_id) = {
        let s = state.lock().unwrap();
        if s.child.is_some() {
            return Ok(()); // already running
        }
        (s.port, s.event_id.clone())
    };

    let candidates = resolve_server_binaries(app);
    if candidates.is_empty() {
        let msg = "Could not find eventbox-server binary or Deno runtime.\n\n\
                   The bundled server binary may be missing. Reinstall EventBox or \
                   install Deno manually: https://deno.land/#installation"
            .to_string();
        eprintln!("[EventBox] {}", msg);
        let _ = app.emit(
            "server-status",
            serde_json::json!({
                "running": false,
                "error": &msg,
            }),
        );
        return Err(msg);
    }

    let deno_args = |ts_path: &std::path::Path| -> Vec<String> {
        vec![
            "run".into(),
            "--allow-net".into(),
            "--allow-read".into(),
            "--allow-write".into(),
            "--allow-env".into(),
            "--allow-ffi".into(),
            "--unstable-ffi".into(),
            ts_path.to_string_lossy().into(),
        ]
    };

    let mut last_error = String::new();

    for (binary, label) in &candidates {
        let mut cmd = match binary {
            ServerBinary::Native(path) => {
                let mut c = Command::new(path);
                c.env("EVENTBOX_PORT", port.to_string())
                    .env("EVENTBOX_EVENT_ID", &event_id)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                c
            }
            ServerBinary::SidecarDeno(deno_path, ts_path) => {
                let mut c = Command::new(deno_path);
                c.args(deno_args(ts_path))
                    .env("EVENTBOX_PORT", port.to_string())
                    .env("EVENTBOX_EVENT_ID", &event_id)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                c
            }
            ServerBinary::SystemDeno(ts_path) => {
                let mut c = Command::new("deno");
                c.args(deno_args(ts_path))
                    .env("EVENTBOX_PORT", port.to_string())
                    .env("EVENTBOX_EVENT_ID", &event_id)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                c
            }
        };

        match cmd.spawn() {
            Ok(mut child) => {
                // Give the process a moment to crash or stabilize.
                // Corrupt/incompatible binaries exit instantly, so a short
                // sleep is enough to detect them without slowing normal startup.
                // NOTE: The mutex is NOT held here — it was dropped above.
                std::thread::sleep(std::time::Duration::from_millis(500));

                match child.try_wait() {
                    Ok(Some(_exit_status)) => {
                        // Process already exited — collect stderr for diagnostics
                        let mut stderr_text = String::new();
                        if let Some(mut pipe) = child.stderr.take() {
                            let _ = pipe.read_to_string(&mut stderr_text);
                        }
                        let detail = if stderr_text.trim().is_empty() {
                            format!("exited with {}", _exit_status)
                        } else {
                            stderr_text.trim().to_string()
                        };
                        eprintln!(
                            "[EventBox] {} crashed on startup: {} \u{2014} trying next fallback",
                            label, detail
                        );
                        last_error = format!("{}: {}", label, detail);
                        continue; // try next candidate
                    }
                    Ok(None) => {
                        // Process is still running — success!
                        eprintln!(
                            "[EventBox] {} started successfully (pid={})",
                            label,
                            child.id()
                        );

                        // Read stdout in background to capture room code
                        if let Some(stdout) = child.stdout.take() {
                            let app_handle = app.clone();
                            std::thread::spawn(move || {
                                let reader = BufReader::new(stdout);
                                for line in reader.lines().map_while(Result::ok) {
                                    println!("[EventBox] {}", line);
                                    if line.contains("Room code:") {
                                        if let Some(code) = line.split("Room code:").nth(1) {
                                            let code = code.trim().to_string();
                                            {
                                                let state_ref =
                                                    app_handle.state::<Mutex<ServerState>>();
                                                let mut s = state_ref.lock().unwrap();
                                                s.room_code = Some(code.clone());
                                            }
                                            let _ = app_handle.emit(
                                                "server-status",
                                                serde_json::json!({
                                                    "running": true,
                                                    "room_code": code,
                                                }),
                                            );
                                        }
                                    }
                                }
                            });
                        }

                        // Re-acquire the lock to store the child and bump generation.
                        let mut s = state.lock().unwrap();

                        // Guard against a concurrent start that raced us.
                        if s.child.is_some() {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Ok(());
                        }

                        // Read stderr for error reporting.
                        // Bump the generation counter and capture it so the
                        // thread can later tell whether this specific process
                        // instance is still the "current" one.
                        s.generation += 1;
                        let spawn_generation = s.generation;
                        if let Some(stderr) = child.stderr.take() {
                            let app_handle2 = app.clone();
                            std::thread::spawn(move || {
                                let reader = BufReader::new(stderr);
                                let mut error_buf = String::new();
                                for line in reader.lines().map_while(Result::ok) {
                                    eprintln!("[EventBox stderr] {}", line);
                                    error_buf.push_str(&line);
                                    error_buf.push('\n');
                                }
                                let suppress = {
                                    let state_ref =
                                        app_handle2.state::<Mutex<ServerState>>();
                                    let s = state_ref.lock().unwrap();
                                    s.child.is_none() || s.generation != spawn_generation
                                };

                                if !suppress {
                                    let error_msg = if error_buf.trim().is_empty() {
                                        "Server process exited unexpectedly with no output.\n\
                                         The bundled server binary may be missing or incompatible \
                                         with your system."
                                            .to_string()
                                    } else {
                                        error_buf.trim().to_string()
                                    };
                                    let _ = app_handle2.emit(
                                        "server-status",
                                        serde_json::json!({
                                            "running": false,
                                            "error": error_msg,
                                        }),
                                    );
                                }
                            });
                        }

                        s.child = Some(child);

                        // Fix #7: Write PID file for orphan cleanup on next launch
                        if let Some(ref child) = s.child {
                            write_pidfile(child.id());
                        }

                        update_tray(app, true);

                        let _ = app.emit(
                            "server-status",
                            serde_json::json!({
                                "running": true,
                                "port": port,
                                "event_id": event_id,
                            }),
                        );

                        return Ok(());
                    }
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        eprintln!(
                            "[EventBox] try_wait error for {}: {} \u{2014} trying next fallback",
                            label, e
                        );
                        last_error = format!("{}: try_wait error: {}", label, e);
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("[EventBox] failed to spawn {}: {}", label, e);
                last_error = format!("Failed to start {}: {}", label, e);
                continue;
            }
        }
    }

    // All candidates failed
    let error_msg = format!(
        "All server binary options failed.\nLast error: {}\n\n\
         If this persists, reinstall EventBox or install Deno manually:\n\
         https://deno.land/#installation",
        last_error
    );
    eprintln!("[EventBox] {}", error_msg);
    let _ = app.emit(
        "server-status",
        serde_json::json!({
            "running": false,
            "error": &error_msg,
        }),
    );
    Err(error_msg)
}

fn stop_server(state: &Mutex<ServerState>, app: &tauri::AppHandle) {
    let mut s = state.lock().unwrap();
    let was_running = s.child.is_some();
    if let Some(mut child) = s.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    s.room_code = None;

    // Fix #7: Remove PID file on clean shutdown
    remove_pidfile();

    update_tray(app, false);
    // Only emit the event if a server was actually running. This avoids
    // sending a bare { running: false } during set_event_id_and_start()
    // when no previous server existed, which would disarm the frontend's
    // safety-net timeout.
    if was_running {
        let _ = app.emit("server-status", serde_json::json!({ "running": false }));
    }
}

fn update_tray(app: &tauri::AppHandle, running: bool) {
    let tray_menu = app.state::<Mutex<Option<Menu<tauri::Wry>>>>();
    let guard = tray_menu.lock().unwrap();
    if let Some(menu) = guard.as_ref() {
        if let Some(item) = menu.get("status") {
            if let Some(mi) = item.as_menuitem() {
                let _ = mi.set_text(if running {
                    "EventBox \u{2014} Running"
                } else {
                    "EventBox \u{2014} Stopped"
                });
            }
        }
        if let Some(item) = menu.get("start") {
            if let Some(mi) = item.as_menuitem() {
                let _ = mi.set_enabled(!running);
            }
        }
        if let Some(item) = menu.get("stop") {
            if let Some(mi) = item.as_menuitem() {
                let _ = mi.set_enabled(running);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

fn get_local_ips() -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(ip) = local_ip_address::local_ip() {
        ips.push(ip.to_string());
    }
    if let Ok(networks) = local_ip_address::list_afinet_netifas() {
        for (_, ip) in networks {
            let s = ip.to_string();
            if !s.starts_with("127.") && !s.contains("::1") && !ips.contains(&s) {
                ips.push(s);
            }
        }
    }
    ips
}

// ---------------------------------------------------------------------------
// IPC commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn set_event_id_and_start(
    state: tauri::State<'_, Mutex<ServerState>>,
    app_handle: tauri::AppHandle,
    event_id: String,
    port: Option<u16>,
) -> Result<(), String> {
    if event_id.trim().is_empty() {
        return Err("Event ID cannot be empty".into());
    }
    stop_server(&state, &app_handle);
    {
        let mut s = state.lock().unwrap();
        s.event_id = event_id.trim().to_string();
        if let Some(p) = port {
            s.port = p;
        }
    }
    start_server(&state, &app_handle)?;
    Ok(())
}

#[tauri::command]
fn stop_server_cmd(
    state: tauri::State<'_, Mutex<ServerState>>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    stop_server(&state, &app_handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// App entry point (shared by desktop and mobile)
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let mut event_id = std::env::var("EVENTBOX_EVENT_ID").unwrap_or_default();
    let mut port: u16 = std::env::var("EVENTBOX_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--event-id" if i + 1 < args.len() => {
                event_id = args[i + 1].clone();
                i += 2;
            }
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(8787);
                i += 2;
            }
            _ => i += 1,
        }
    }

    // Fix #7: Clean up any orphaned server process from a previous crash
    cleanup_orphan();

    let server_state = Mutex::new(ServerState {
        child: None,
        room_code: None,
        port,
        event_id: event_id.clone(),
        generation: 0,
    });

    let tray_menu_state: Mutex<Option<Menu<tauri::Wry>>> = Mutex::new(None);

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(server_state)
        .manage(tray_menu_state)
        .invoke_handler(tauri::generate_handler![
            set_event_id_and_start,
            stop_server_cmd,
            check_deno
        ])
        .setup(|app| {
            // Build tray menu
            let status_item =
                MenuItemBuilder::with_id("status", "EventBox \u{2014} Stopped")
                    .enabled(false)
                    .build(app)?;
            // Fix #2: Add "Show Dashboard" menu item
            let show_item = MenuItemBuilder::with_id("show", "Show Dashboard")
                .enabled(true)
                .build(app)?;

            let start_item = MenuItemBuilder::with_id("start", "Start Server")
                .enabled(true)
                .build(app)?;
            let stop_item = MenuItemBuilder::with_id("stop", "Stop Server")
                .enabled(false)
                .build(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Quit")
                .enabled(true)
                .build(app)?;

            let menu = MenuBuilder::new(app)
                .item(&status_item)
                .separator()
                .item(&show_item) // Fix #2
                .item(&start_item)
                .item(&stop_item)
                .separator()
                .item(&quit_item)
                .build()?;

            // Store menu in state so update_tray can access it
            {
                let tray_menu = app.state::<Mutex<Option<Menu<tauri::Wry>>>>();
                let mut guard = tray_menu.lock().unwrap();
                *guard = Some(menu.clone());
            }

            let _tray = TrayIconBuilder::with_id("main-tray")
                .icon(app.default_window_icon().cloned().unwrap())
                .icon_as_template(true)
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| {
                    let state = app.state::<Mutex<ServerState>>();
                    match event.id().as_ref() {
                        // Fix #2: Handle "Show Dashboard" menu item
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                        "start" => {
                            let _ = start_server(&state, app);
                        }
                        "stop" => stop_server(&state, app),
                        "quit" => {
                            stop_server(&state, app);
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                })
                // Fix #2: Left-click tray icon shows main window
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click {
                        button: tauri::tray::MouseButton::Left,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            // Emit local IPs and auto-start if event_id is set
            let handle = app.handle().clone();
            let ips = get_local_ips();
            let _ = handle.emit("local-ips", serde_json::json!({ "ips": ips }));
            {
                let state = app.state::<Mutex<ServerState>>();
                let s = state.lock().unwrap();
                if !s.event_id.is_empty() {
                    drop(s);
                    if let Err(e) = start_server(&state, &handle) {
                        eprintln!("[EventBox] auto-start failed: {}", e);
                    }
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("Error running EventBox");
}
